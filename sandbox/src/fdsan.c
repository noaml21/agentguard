#define _GNU_SOURCE
#include "fdsan.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Is fd one we must keep open (0,1,2 or a user-kept fd)? report_fd is handled
 * separately because it needs CLOEXEC rather than staying open across exec. */
static int is_kept(int fd, const struct fdsan_policy *p)
{
    if (fd == 0 || fd == 1 || fd == 2)
        return 1;
    for (size_t i = 0; i < p->nkeep; i++)
        if (p->keep[i] == fd)
            return 1;
    return 0;
}

static int set_cloexec(int fd, int on)
{
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0)
        return -1;
    int want = on ? (flags | FD_CLOEXEC) : (flags & ~FD_CLOEXEC);
    if (want == flags)
        return 0;
    return fcntl(fd, F_SETFD, want);
}

/* Close everything except kept fds and report_fd by scanning /proc/self/fd.
 * Used when close_range is unavailable. */
static int close_via_proc(const struct fdsan_policy *p)
{
    int dirfd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
        return -1;
    /* Read raw linux_dirent64 without pulling in opendir's heap use. */
    char buf[4096];
    for (;;) {
        long n = syscall(SYS_getdents64, dirfd, buf, sizeof buf);
        if (n < 0) {
            close(dirfd);
            return -1;
        }
        if (n == 0)
            break;
        for (long off = 0; off < n;) {
            /* struct linux_dirent64: d_ino(8) d_off(8) d_reclen(2) d_type(1) name */
            unsigned short reclen;
            __builtin_memcpy(&reclen, buf + off + 16, sizeof reclen);
            const char *name = buf + off + 19;
            off += reclen;
            if (name[0] < '0' || name[0] > '9')
                continue;
            int fd = (int)strtol(name, NULL, 10);
            if (fd == dirfd || fd == p->report_fd || is_kept(fd, p))
                continue;
            close(fd);
        }
    }
    close(dirfd);
    return 0;
}

int fdsan_apply(const struct fdsan_policy *policy)
{
    long rc = -1;
#ifdef SYS_close_range
    /* Close all fds >= 3, then reopen-guard the ones we keep. Simpler and more
     * robust than computing gaps: close the whole high range, but first move the
     * fds we keep out of harm's way is unnecessary because we just skip them via
     * a per-fd approach below. We instead close ranges between kept fds. */
    /* Build a sorted set: 0,1,2, report_fd, and user keeps. */
    int kept[3 + 64];
    size_t nk = 0;
    kept[nk++] = 0;
    kept[nk++] = 1;
    kept[nk++] = 2;
    kept[nk++] = policy->report_fd;
    for (size_t i = 0; i < policy->nkeep && nk < sizeof(kept) / sizeof(kept[0]); i++)
        kept[nk++] = policy->keep[i];
    /* insertion sort (tiny) */
    for (size_t i = 1; i < nk; i++) {
        int v = kept[i];
        size_t j = i;
        while (j > 0 && kept[j - 1] > v) {
            kept[j] = kept[j - 1];
            j--;
        }
        kept[j] = v;
    }
    /* Close (lo .. next_kept-1) ranges. */
    unsigned lo = 0;
    int ok = 1;
    for (size_t i = 0; i < nk; i++) {
        int k = kept[i];
        if ((unsigned)k > lo) {
            if (syscall(SYS_close_range, lo, (unsigned)k - 1, 0) != 0) {
                ok = 0;
                break;
            }
        }
        lo = (unsigned)k + 1;
    }
    if (ok && syscall(SYS_close_range, lo, ~0U, 0) != 0)
        ok = 0;
    rc = ok ? 0 : -1;
#endif
    if (rc != 0) {
        if (close_via_proc(policy) != 0)
            return -1;
    }
    /* report_fd must close at exec (its EOF signals success to the parent). */
    if (set_cloexec(policy->report_fd, 1) != 0)
        return -1;
    /* stdio and user-kept fds must survive exec. */
    if (set_cloexec(0, 0) != 0 || set_cloexec(1, 0) != 0 || set_cloexec(2, 0) != 0)
        return -1;
    for (size_t i = 0; i < policy->nkeep; i++)
        if (set_cloexec(policy->keep[i], 0) != 0)
            return -1;
    return 0;
}
