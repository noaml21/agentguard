#define _GNU_SOURCE
#include "lifecycle.h"
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
 * throughout. pgid equals the child pid. */
static void terminate_group(pid_t pgid, pid_t main_pid, int *main_done,
                            int *main_status)
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
    kill(-pgid, SIGKILL);
    reap_tree(now_ms() + AG_TEARDOWN_GRACE_MS);
}

/* Child side: new process group, default signal disposition, FD sanitation,
 * then exec. Never returns on success. */
static void child_exec(const struct options *opts, int report_fd) __attribute__((noreturn));
static void child_exec(const struct options *opts, int report_fd)
{
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
        int err = errno;
        (void)ag_write_all(report_fd, &err, sizeof err);
        _exit(AG_EXIT_SETUP_FAILURE);
    }

    /* Later phases install Landlock/seccomp here, immediately before exec. */

    execvp(opts->argv[0], opts->argv);
    int err = errno; /* exec failed */
    (void)ag_write_all(report_fd, &err, sizeof err);
    _exit(AG_EXIT_EXEC_FAILURE);
}

int lifecycle_run(const struct options *opts)
{
    /* Orphaned descendants reparent to us so we can reap the whole tree. */
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0)
        ag_warn_errno("PR_SET_CHILD_SUBREAPER (descendant reaping may be incomplete)");

    int report[2];
    if (pipe2(report, O_CLOEXEC) != 0) {
        ag_warn_errno("pipe2");
        return AG_EXIT_SETUP_FAILURE;
    }

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
        return AG_EXIT_SETUP_FAILURE;
    }
    if (child == 0) {
        close(report[0]);
        child_exec(opts, report[1]);
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
            terminate_group(child, child, &main_done, &main_status);
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

    /* Check for an exec/setup failure report from the child. */
    int report_err = 0;
    if (fcntl(report[0], F_SETFL, O_NONBLOCK) == 0) {
        int buf;
        if (ag_read_all(report[0], &buf, sizeof buf) == (long)sizeof buf)
            report_err = buf;
    }
    close(report[0]);

    /* Tear down anything still alive in the group (reparented descendants). */
    terminate_group(child, child, &main_done, &main_status);

    if (tty_fd >= 0 && saved_fg > 0) {
        (void)tcsetpgrp(tty_fd, saved_fg);
        signal(SIGTTOU, SIG_DFL);
    }
    if (sfd >= 0)
        close(sfd);
    sigprocmask(SIG_SETMASK, &old, NULL);

    if (report_err != 0) {
        errno = report_err;
        ag_warn_errno(opts->argv[0]);
        return AG_EXIT_EXEC_FAILURE;
    }
    if (timed_out)
        return AG_EXIT_TIMEOUT;
    if (WIFEXITED(main_status))
        return WEXITSTATUS(main_status);
    if (WIFSIGNALED(main_status))
        return 128 + WTERMSIG(main_status);
    return AG_EXIT_SETUP_FAILURE;
}
