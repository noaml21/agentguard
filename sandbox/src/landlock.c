#define _GNU_SOURCE
#include "landlock.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* UAPI fallbacks so we build against older headers; values are ABI-stable. */
#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif

static long ll_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size,
                              uint32_t flags)
{
    return syscall(SYS_landlock_create_ruleset, attr, size, flags);
}
static long ll_add_rule(int ruleset_fd, enum landlock_rule_type type,
                        const void *attr, uint32_t flags)
{
    return syscall(SYS_landlock_add_rule, ruleset_fd, type, attr, flags);
}
static long ll_restrict_self(int ruleset_fd, uint32_t flags)
{
    return syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}

int ll_abi(void)
{
    long v = ll_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (v < 0)
        return -1;
    return (int)v;
}

/* Base filesystem rights present since ABI 1. */
#define LL_BASE ( \
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | \
    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | \
    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | \
    LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | \
    LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK | \
    LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
    LANDLOCK_ACCESS_FS_MAKE_SYM)

/* Rights granted on read-only paths: read files, list dirs, execute programs.
 * We intentionally do NOT handle IOCTL_DEV (ABI5): device ioctls on the
 * inherited TTY must keep working for an interactive agent, and restricting them
 * is a hardening extra outside the Core filesystem guarantee (documented). */
static uint64_t read_grant(void)
{
    return LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
           LANDLOCK_ACCESS_FS_EXECUTE;
}

/* Compute the handled set for the running ABI (feature-by-feature). */
static uint64_t handled_for_abi(int abi)
{
    uint64_t h = LL_BASE;
    if (abi >= 2)
        h |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3)
        h |= LANDLOCK_ACCESS_FS_TRUNCATE;
    return h;
}

/* Full read+write+manage rights on a writable root, masked to handled. */
static uint64_t write_grant(uint64_t handled)
{
    uint64_t g = LL_BASE; /* execute/read/write/remove/make all included */
    g |= LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE;
    return g & handled;
}

/* Add one path_beneath rule. Missing optional paths are skipped (rc 1). */
static int add_path(int ruleset_fd, const char *path, uint64_t access, int required)
{
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        if (!required && (errno == ENOENT || errno == EACCES))
            return 1; /* optional default that isn't present here */
        ag_warnf("landlock: cannot open %s: %s", path, strerror(errno));
        return -1;
    }
    struct landlock_path_beneath_attr attr = {
        .allowed_access = access,
        .parent_fd = fd,
    };
    long rc = ll_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
    int saved = errno;
    close(fd);
    if (rc != 0) {
        errno = saved;
        ag_warnf("landlock: add_rule %s failed: %s", path, strerror(saved));
        return -1;
    }
    return 0;
}

int ll_restrict_fs(const struct ag_policy *pol)
{
    int abi = ll_abi();
    if (abi < 1) {
        if (errno == 0)
            errno = ENOSYS;
        return -1;
    }
    uint64_t handled = handled_for_abi(abi);

    struct landlock_ruleset_attr rattr = {.handled_access_fs = handled};
    int ruleset_fd = (int)ll_create_ruleset(&rattr, sizeof rattr, 0);
    if (ruleset_fd < 0)
        return -1;

    uint64_t rd = read_grant();
    uint64_t wr = write_grant(handled);
    int ok = 1;

    /* Read-only paths (system dirs + explicit --allow-read). */
    for (size_t i = 0; i < pol->nread && ok; i++)
        if (add_path(ruleset_fd, pol->read_paths[i], rd, 0) < 0)
            ok = 0;

    /* Writable workspace (required). */
    if (ok && pol->workspace)
        if (add_path(ruleset_fd, pol->workspace, wr, 1) < 0)
            ok = 0;

    /* Extra writable roots (--allow-write). */
    for (size_t i = 0; i < pol->nwrite && ok; i++)
        if (add_path(ruleset_fd, pol->write_paths[i], wr, 1) < 0)
            ok = 0;

    /* Writable device nodes needed by ordinary programs (best-effort). */
    static const char *kDevWrite[] = {"/dev/null", "/dev/zero", "/dev/full",
                                      "/dev/tty", "/dev/ptmx", "/dev/pts",
                                      "/dev/random", "/dev/urandom"};
    for (size_t i = 0; i < sizeof(kDevWrite) / sizeof(kDevWrite[0]) && ok; i++)
        if (add_path(ruleset_fd, kDevWrite[i],
                     (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE) & handled,
                     0) < 0)
            ok = 0;

    if (!ok) {
        int saved = errno;
        close(ruleset_fd);
        errno = saved;
        return -1;
    }

    if (ll_restrict_self(ruleset_fd, 0) != 0) {
        int saved = errno;
        close(ruleset_fd);
        errno = saved;
        return -1;
    }
    close(ruleset_fd);
    return 0;
}
