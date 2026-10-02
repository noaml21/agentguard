/*
 * capprobe: unprivileged, read-only kernel capability probe for AgentGuard V2.
 *
 * Every probe either queries the kernel or performs a restriction inside a
 * short-lived forked child, so the calling process is never modified.
 * Output is one "key=value" line per fact so it can be diffed across hosts.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

static void report_landlock(void)
{
    long abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
                       LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        printf("landlock_abi=unavailable\nlandlock_errno=%s\n", strerror(errno));
        return;
    }
    printf("landlock_abi=%ld\n", abi);
    printf("landlock_fs=%s\n", abi >= 1 ? "yes" : "no");
    printf("landlock_refer=%s\n", abi >= 2 ? "yes" : "no");
    printf("landlock_truncate=%s\n", abi >= 3 ? "yes" : "no");
    printf("landlock_net_tcp=%s\n", abi >= 4 ? "yes" : "no");
    printf("landlock_ioctl_dev=%s\n", abi >= 5 ? "yes" : "no");
    printf("landlock_scope_abstract_unix_and_signal=%s\n", abi >= 6 ? "yes" : "no");
    printf("landlock_pathname_unix=%s\n", abi >= 9 ? "yes" : "no");
    printf("landlock_net_udp=%s\n", abi >= 10 ? "yes" : "no");
}

/* Run fn in a forked child; return its exit status (0 = success). */
static int in_child(int (*fn)(void))
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0)
        _exit(fn());
    int status;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int try_nnp(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return 1;
    return prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 ? 0 : 2;
}

static int try_seccomp_filter(void)
{
    /* SECCOMP_GET_ACTION_AVAIL does not install anything. */
    unsigned int action = SECCOMP_RET_KILL_PROCESS;
    if (syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action) != 0)
        return 1;
    action = SECCOMP_RET_ERRNO;
    if (syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action) != 0)
        return 2;
    return 0;
}

static int try_userns(void) { return unshare(CLONE_NEWUSER) == 0 ? 0 : errno; }

static int try_userns_netns(void)
{
    if (unshare(CLONE_NEWUSER) != 0)
        return 100;
    return unshare(CLONE_NEWNET) == 0 ? 0 : errno;
}

static int try_userns_pidns(void)
{
    if (unshare(CLONE_NEWUSER) != 0)
        return 100;
    return unshare(CLONE_NEWPID) == 0 ? 0 : errno;
}

/* Can we write uid_map after unshare? AppArmor userns restriction blocks this. */
static int try_userns_uidmap(void)
{
    uid_t uid = getuid();
    if (unshare(CLONE_NEWUSER) != 0)
        return 100;
    int fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) {
        if (write(fd, "deny", 4) != 4) { close(fd); return 101; }
        close(fd);
    }
    char buf[64];
    int n = snprintf(buf, sizeof buf, "0 %u 1", uid);
    fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd < 0)
        return 102;
    int ok = write(fd, buf, (size_t)n) == n;
    int err = errno;
    close(fd);
    return ok ? 0 : (err ? err : 103);
}

static int try_userns_mountns(void)
{
    if (unshare(CLONE_NEWUSER) != 0)
        return 100;
    return unshare(CLONE_NEWNS) == 0 ? 0 : errno;
}

static int try_close_range(void)
{
#ifdef SYS_close_range
    /* Closing a range with nothing open above 1<<20 is harmless. */
    return syscall(SYS_close_range, 1U << 20, ~0U, 0) == 0 ? 0 : errno;
#else
    return 200;
#endif
}

static int try_pidfd(void)
{
#ifdef SYS_pidfd_open
    int fd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (fd < 0)
        return errno;
    close(fd);
    return 0;
#else
    return 200;
#endif
}

static int try_subreaper(void)
{
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0)
        return errno;
    int v = 0;
    prctl(PR_GET_CHILD_SUBREAPER, &v, 0, 0, 0);
    return v == 1 ? 0 : 1;
}

static void result(const char *key, int rc)
{
    if (rc == 0)
        printf("%s=yes\n", key);
    else if (rc > 0 && rc < 100)
        printf("%s=no (%s)\n", key, strerror(rc));
    else
        printf("%s=no (code %d)\n", key, rc);
}

int main(void)
{
    printf("euid=%u\n", (unsigned)geteuid());
    report_landlock();
    result("no_new_privs", in_child(try_nnp));
    result("seccomp_filter_actions", in_child(try_seccomp_filter));
    printf("seccomp_mode_self=%d\n", prctl(PR_GET_SECCOMP, 0, 0, 0, 0));
    result("unpriv_userns", in_child(try_userns));
    result("unpriv_userns_uid_map", in_child(try_userns_uidmap));
    result("unpriv_userns_netns", in_child(try_userns_netns));
    result("unpriv_userns_pidns", in_child(try_userns_pidns));
    result("unpriv_userns_mountns", in_child(try_userns_mountns));
    result("close_range", in_child(try_close_range));
    result("pidfd_open", in_child(try_pidfd));
    result("child_subreaper", in_child(try_subreaper));
    return 0;
}
