#define _GNU_SOURCE
#include "lifecycle.h"
#include "cgroup.h"
#include "fdsan.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Signals the supervisor manages via signalfd. SIGCHLD tells us the tree
 * changed; the terminating signals are forwarded to the child's process group;
 * SIGWINCH is forwarded so a TUI target resizes. */
static const int kManagedSignals[] = {
    SIGCHLD, SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGWINCH,
};

/* Grace period between SIGTERM and SIGKILL during teardown. */
#define AG_TEARDOWN_GRACE_MS 2000

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Reap any exited descendants. If the main child is among them, store its raw
 * wait status in *main_status and set *main_done. Returns after WNOHANG drains. */
static void reap_ready(pid_t main_pid, int *main_done, int *main_status)
{
    for (;;) {
        int status;
        pid_t pid = waitpid(-1, &status, WNOHANG);
        if (pid <= 0)
            break;
        if (pid == main_pid) {
            *main_done = 1;
            *main_status = status;
        }
    }
}

/* Block until every remaining descendant is reaped or the deadline passes. */
static void reap_tree(long deadline_ms)
{
    for (;;) {
        int status;
        pid_t pid = waitpid(-1, &status, WNOHANG);
        if (pid > 0)
            continue;
        if (pid < 0 && errno == ECHILD)
            return; /* nothing left */
        if (now_ms() >= deadline_ms)
            return;
        struct timespec nap = {0, 20 * 1000 * 1000};
        nanosleep(&nap, NULL);
    }
}

/* SIGTERM then, after a grace period, SIGKILL the whole process group, reaping
 * throughout. pgid equals the child pid. If the tree is in an owned cgroup,
 * cgroup.kill also takes out descendants that left the group via setsid(). */
static void terminate_group(pid_t pgid, pid_t main_pid, int *main_done,
                            int *main_status, const struct ag_cgroup *cg)
{
    kill(-pgid, SIGTERM);
    long deadline = now_ms() + AG_TEARDOWN_GRACE_MS;
    while (now_ms() < deadline) {
        reap_ready(main_pid, main_done, main_status);
        if (waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD)
            break;
        struct timespec nap = {0, 20 * 1000 * 1000};
        nanosleep(&nap, NULL);
    }
    cg_kill(cg);
    kill(-pgid, SIGKILL);
    reap_tree(now_ms() + AG_TEARDOWN_GRACE_MS);
}

/* Child side: new process group, default signal disposition, FD sanitation,
 * enforcement layers, then exec. Never returns on success. */
/* Per-process resource limits (Phase 7.1). Soft and hard are set equal so the
 * target cannot raise them back (raising a hard limit needs CAP_SYS_RESOURCE).
 * Inherited across fork/exec, but each process gets its own copy: these bound
 * every process individually, never the tree in aggregate. */
static int apply_rlimits(const struct options *opts)
{
    /* Core dumps off: a dump of an agent process can hold secrets, and a piped
     * core_pattern hands it to a helper running outside the sandbox. */
    struct rlimit rl = {0, 0};
    if (setrlimit(RLIMIT_CORE, &rl) != 0)
        return -1;
    if (opts->max_fsize > 0) {
        rl.rlim_cur = rl.rlim_max = (rlim_t)opts->max_fsize;
        if (setrlimit(RLIMIT_FSIZE, &rl) != 0)
            return -1;
    }
    if (opts->max_nofile > 0) {
        rl.rlim_cur = rl.rlim_max = (rlim_t)opts->max_nofile;
        if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
            return -1;
    }
    return 0;
}

static void child_exec(const struct options *opts, const struct ag_negotiation *neg,
                       int report_fd, int cgroup_procs_fd) __attribute__((noreturn));
static void child_exec(const struct options *opts, const struct ag_negotiation *neg,
                       int report_fd, int cgroup_procs_fd)
{
    /* Join the owned cgroup before anything else, so every later descendant is
     * created inside it. The outcome is reported by the cgroup_kill layer. */
    int cgroup_join_err = cg_join(cgroup_procs_fd) == 0 ? 0 : errno;

    /* Restore default handlers and unblock everything so the target sees normal
     * signal behavior. */
    sigset_t empty;
    sigemptyset(&empty);
    sigprocmask(SIG_SETMASK, &empty, NULL);
    for (size_t i = 0; i < sizeof(kManagedSignals) / sizeof(kManagedSignals[0]); i++)
        signal(kManagedSignals[i], SIG_DFL);

    /* Own process group so the supervisor can signal the whole tree. */
    if (setpgid(0, 0) != 0) {
        int err = errno;
        (void)ag_write_all(report_fd, &err, sizeof err);
        _exit(AG_EXIT_SETUP_FAILURE);
    }

    struct fdsan_policy pol = {
        .keep = opts->nkeep ? opts->keep_fds : NULL,
        .nkeep = opts->nkeep,
        .report_fd = report_fd,
    };
    if (fdsan_apply(&pol) != 0) {
        struct ag_report rep = {.tag = AG_REPORT_SETUP_FAIL, .layer = -1,
                                .err = errno, .applied_mask = 0};
        (void)ag_write_all(report_fd, &rep, sizeof rep);
        _exit(AG_EXIT_SETUP_FAILURE);
    }

    if (apply_rlimits(opts) != 0) {
        struct ag_report rep = {.tag = AG_REPORT_SETUP_FAIL, .layer = -1,
                                .err = errno, .applied_mask = 0};
        (void)ag_write_all(report_fd, &rep, sizeof rep);
        _exit(AG_EXIT_SETUP_FAILURE);
    }

    /* Build the filesystem/network policy from options (Phase 8 will also load a
     * policy file into this same struct). */
    struct ag_policy fspol;
    ag_policy_from_options(&fspol, opts);
    fspol.cgroup_join_err = cgroup_join_err;

    /* Enforcement layers install here, immediately before exec. On failure the
     * child reports and exits; the target never runs (fail-closed contract). */
    if (ag_apply_layers(neg, &fspol, report_fd) != 0)
        _exit(AG_EXIT_SETUP_FAILURE);

    execvp(opts->argv[0], opts->argv);
    struct ag_report rep = {.tag = AG_REPORT_EXEC_FAIL, .layer = -1,
                            .err = errno, .applied_mask = neg->requested_mask};
    (void)ag_write_all(report_fd, &rep, sizeof rep);
    _exit(AG_EXIT_EXEC_FAILURE);
}

int lifecycle_run(const struct options *opts, const struct ag_negotiation *neg)
{
    /* Orphaned descendants reparent to us so we can reap the whole tree. */
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0)
        ag_warn_errno("PR_SET_CHILD_SUBREAPER (descendant reaping may be incomplete)");

    int report[2];
    if (pipe2(report, O_CLOEXEC) != 0) {
        ag_warn_errno("pipe2");
        return AG_EXIT_SETUP_FAILURE;
    }

    /* Owned cgroup for tree kill, when the negotiated layer set includes it. A
     * creation failure leaves procs_fd at -1, so the child's join fails and the
     * layer is reported not applied; teardown then relies on the process group. */
    struct ag_cgroup cg = {.parent_fd = -1, .procs_fd = -1, .kill_fd = -1, .name = ""};
    if ((neg->requested_mask & AG_LAYER_BIT(AG_LAYER_CGROUP_KILL)) && cg_create(&cg) != 0 &&
        opts->verbose)
        ag_warn_errno("cgroup_kill: creating owned cgroup");

    int tty_fd = isatty(STDIN_FILENO) ? STDIN_FILENO : -1;
    pid_t saved_fg = -1;
    if (tty_fd >= 0)
        saved_fg = tcgetpgrp(tty_fd);

    /* Block managed signals before fork so none are missed between fork and the
     * signalfd being ready. The child resets them. */
    sigset_t block, old;
    sigemptyset(&block);
    for (size_t i = 0; i < sizeof(kManagedSignals) / sizeof(kManagedSignals[0]); i++)
        sigaddset(&block, kManagedSignals[i]);
    sigprocmask(SIG_BLOCK, &block, &old);

    pid_t child = fork();
    if (child < 0) {
        ag_warn_errno("fork");
        sigprocmask(SIG_SETMASK, &old, NULL);
        close(report[0]);
        close(report[1]);
        cg_destroy(&cg);
        return AG_EXIT_SETUP_FAILURE;
    }
    if (child == 0) {
        close(report[0]);
        child_exec(opts, neg, report[1], cg.procs_fd);
        _exit(AG_EXIT_EXEC_FAILURE); /* unreachable */
    }

    /* Parent (supervisor). */
    close(report[1]);
    (void)setpgid(child, child); /* race-safe with the child's own setpgid */

    if (tty_fd >= 0) {
        /* Hand the terminal to the child's group; ignore SIGTTOU so our own
         * tcsetpgrp from the (background) supervisor is not stopped. */
        signal(SIGTTOU, SIG_IGN);
        if (tcsetpgrp(tty_fd, child) != 0 && errno != ENOTTY)
            ag_warn_errno("tcsetpgrp");
    }

    int sfd = signalfd(-1, &block, SFD_CLOEXEC | SFD_NONBLOCK);
    if (sfd < 0) {
        ag_warn_errno("signalfd");
        /* Best-effort: still wait for the child. */
    }

    long deadline = opts->timeout_ms > 0 ? now_ms() + opts->timeout_ms : -1;
    int main_done = 0, main_status = 0, timed_out = 0;

    while (!main_done) {
        int poll_timeout = -1;
        if (deadline >= 0) {
            long remaining = deadline - now_ms();
            poll_timeout = remaining > 0 ? (int)remaining : 0;
        }
        struct pollfd pfd = {.fd = sfd, .events = POLLIN};
        int pr = (sfd >= 0) ? poll(&pfd, 1, poll_timeout) : -1;

        if (pr == 0) { /* deadline reached */
            timed_out = 1;
            terminate_group(child, child, &main_done, &main_status, &cg);
            break;
        }
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            /* signalfd unavailable or broken: fall back to a blocking wait. */
            int status;
            if (waitpid(child, &status, 0) == child) {
                main_done = 1;
                main_status = status;
            }
            break;
        }

        struct signalfd_siginfo si;
        while (ag_read_all(sfd, &si, sizeof si) == (long)sizeof si) {
            switch (si.ssi_signo) {
            case SIGCHLD:
                reap_ready(child, &main_done, &main_status);
                break;
            case SIGWINCH:
                kill(-child, SIGWINCH);
                break;
            default: /* SIGINT/SIGTERM/SIGHUP/SIGQUIT: forward to the group */
                kill(-child, (int)si.ssi_signo);
                break;
            }
        }
    }

    /* Drain the child's setup reports. The child writes at most a SETUP_OK (with
     * the applied mask) followed possibly by an EXEC_FAIL, or a single SETUP_FAIL. */
    struct ag_report rep = {.tag = 0, .layer = -1, .err = 0, .applied_mask = 0};
    int have_setup_fail = 0, have_exec_fail = 0;
    uint32_t applied_mask = 0;
    if (fcntl(report[0], F_SETFL, O_NONBLOCK) == 0) {
        struct ag_report r;
        while (ag_read_all(report[0], &r, sizeof r) == (long)sizeof r) {
            if (r.tag == AG_REPORT_SETUP_OK) {
                applied_mask = r.applied_mask;
            } else if (r.tag == AG_REPORT_SETUP_FAIL) {
                have_setup_fail = 1;
                rep = r;
            } else if (r.tag == AG_REPORT_EXEC_FAIL) {
                have_exec_fail = 1;
                rep = r;
            }
        }
    }
    close(report[0]);

    /* Tear down anything still alive in the group (reparented descendants). */
    terminate_group(child, child, &main_done, &main_status, &cg);
    cg_destroy(&cg);

    if (tty_fd >= 0 && saved_fg > 0) {
        (void)tcsetpgrp(tty_fd, saved_fg);
        signal(SIGTTOU, SIG_DFL);
    }
    if (sfd >= 0)
        close(sfd);
    sigprocmask(SIG_SETMASK, &old, NULL);

    if (have_setup_fail) {
        errno = rep.err;
        ag_warnf("required layer %s failed to apply: %s",
                 ag_layer_name((enum ag_layer)rep.layer), strerror(rep.err));
        return AG_EXIT_SETUP_FAILURE;
    }
    if (have_exec_fail) {
        errno = rep.err;
        ag_warn_errno(opts->argv[0]);
        return AG_EXIT_EXEC_FAILURE;
    }
    if (opts->verbose)
        ag_print_status(2, neg, applied_mask, opts->json);
    if (timed_out)
        return AG_EXIT_TIMEOUT;
    if (WIFEXITED(main_status))
        return WEXITSTATUS(main_status);
    if (WIFSIGNALED(main_status))
        return 128 + WTERMSIG(main_status);
    return AG_EXIT_SETUP_FAILURE;
}
