#define _GNU_SOURCE
#include "policyfile.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PF_MAX_BYTES 65536
#define PF_MAX_LINES 1024
#define PF_MAX_LINE (PATH_MAX + 32)
#define PF_MAX_KEY 32

/* The parsed values point into this buffer, which lives for the whole run. */
static char g_buf[PF_MAX_BYTES + 1];

enum {
    S_VERSION = 1u << 0,
    S_WORKSPACE = 1u << 1,
    S_DEFREADS = 1u << 2,
    S_NET = 1u << 3,
    S_TIMEOUT = 1u << 4,
    S_FSIZE = 1u << 5,
    S_NOFILE = 1u << 6,
};

/* Errors never echo values (they may be paths or secrets pasted by mistake);
 * only line numbers and validated key names. */
static int perr(unsigned line, const char *msg)
{
    if (line)
        ag_warnf("policy line %u: %s", line, msg);
    else
        ag_warnf("policy: %s", msg);
    return -1;
}

/* Absolute, normalized: starts with '/', no empty, "." or ".." components, no
 * trailing '/'. "/" itself is accepted only for read rules. */
static int path_ok(const char *p, int writable)
{
    size_t n = strlen(p);
    if (n == 0 || n >= PATH_MAX || p[0] != '/')
        return 0;
    if (n == 1)
        return !writable;
    if (p[n - 1] == '/')
        return 0;
    const char *c = p;
    for (;;) {
        const char *s = c + 1;
        const char *e = strchr(s, '/');
        size_t len = e ? (size_t)(e - s) : strlen(s);
        if (len == 0 || (len == 1 && s[0] == '.') || (len == 2 && s[0] == '.' && s[1] == '.'))
            return 0;
        if (!e)
            return 1;
        c = e;
    }
}

static int once(unsigned *seen, unsigned bit, unsigned line, const char *key)
{
    if (*seen & bit) {
        ag_warnf("policy line %u: duplicate key '%s'", line, key);
        return -1;
    }
    *seen |= bit;
    return 0;
}

static int apply(const char *k, const char *v, unsigned line, struct options *o, unsigned *seen)
{
    if (strcmp(k, "version") == 0) {
        if (once(seen, S_VERSION, line, k) != 0)
            return -1;
        return strcmp(v, "1") == 0 ? 0 : perr(line, "unsupported policy version (supported: 1)");
    }
    if (strcmp(k, "workspace") == 0) {
        if (once(seen, S_WORKSPACE, line, k) != 0)
            return -1;
        if (!path_ok(v, 1))
            return perr(line, "workspace must be an absolute normalized path other than '/'");
        o->workspace = v;
        return 0;
    }
    if (strcmp(k, "read") == 0 || strcmp(k, "write") == 0) {
        int w = k[0] == 'w';
        if (!path_ok(v, w))
            return perr(line, w ? "write must be an absolute normalized path other than '/'"
                                : "read must be an absolute normalized path");
        size_t *n = w ? &o->nwrite : &o->nread;
        if (*n >= AG_MAX_PATHS)
            return perr(line, "too many path rules of this kind");
        if (w)
            o->write_paths[(*n)++] = v;
        else
            o->read_paths[(*n)++] = v;
        return 0;
    }
    if (strcmp(k, "default-reads") == 0) {
        if (once(seen, S_DEFREADS, line, k) != 0)
            return -1;
        if (strcmp(v, "yes") == 0)
            o->no_default_reads = 0;
        else if (strcmp(v, "no") == 0)
            o->no_default_reads = 1;
        else
            return perr(line, "default-reads must be 'yes' or 'no'");
        return 0;
    }
    if (strcmp(k, "net") == 0) {
        if (once(seen, S_NET, line, k) != 0)
            return -1;
        if (strcmp(v, "none") == 0)
            o->net_mode = AG_NET_NONE;
        else if (strcmp(v, "all") == 0)
            o->net_mode = AG_NET_ALL;
        else
            return perr(line, "net must be 'none' or 'all'");
        return 0;
    }
    if (strcmp(k, "timeout") == 0) {
        if (once(seen, S_TIMEOUT, line, k) != 0)
            return -1;
        /* Narrower than strtod: no sign, exponent, hex, inf or nan spellings. */
        const char *dot = strchr(v, '.');
        if (v[0] < '0' || v[0] > '9' || strspn(v, "0123456789.") != strlen(v) ||
            (dot && strchr(dot + 1, '.')))
            return perr(line, "timeout must be seconds, e.g. 30 or 2.5");
        o->timeout_ms = options_parse_timeout_ms(v);
        return o->timeout_ms < 0 ? perr(line, "timeout out of range") : 0;
    }
    if (strcmp(k, "max-file-size") == 0 || strcmp(k, "max-open-files") == 0) {
        int fsize = k[4] == 'f';
        if (once(seen, fsize ? S_FSIZE : S_NOFILE, line, k) != 0)
            return -1;
        long long n = fsize ? options_parse_count(v, 1, LLONG_MAX)
                            : options_parse_count(v, 16, 1 << 20);
        if (n < 0)
            return perr(line, fsize ? "max-file-size must be an integer >= 1"
                                    : "max-open-files must be an integer in [16, 1048576]");
        if (fsize)
            o->max_fsize = n;
        else
            o->max_nofile = n;
        return 0;
    }
    ag_warnf("policy line %u: unknown key '%s'", line, k);
    return -1;
}

static int path_listed(const char *p, const char *const *list, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(p, list[i]) == 0)
            return 1;
    return 0;
}

static int parse(char *buf, size_t len, struct options *o)
{
    unsigned line = 1;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c == '\n') {
            line++;
            continue;
        }
        if (c == 0)
            return perr(line, "NUL byte");
        if (c < 0x20 || c == 0x7f)
            return perr(line, "control character (tabs and CR are not allowed)");
        if (c >= 0x80)
            return perr(line, "non-ASCII byte (policy files are ASCII)");
    }
    buf[len] = '\0';

    unsigned seen = 0;
    line = 0;
    char *p = buf;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl)
            *nl = '\0';
        if (++line > PF_MAX_LINES)
            return perr(0, "too many lines");
        if (strlen(p) > PF_MAX_LINE)
            return perr(line, "line too long");
        if (*p != '\0' && *p != '#') {
            size_t kl = strspn(p, "abcdefghijklmnopqrstuvwxyz-");
            if (kl == 0 || kl > PF_MAX_KEY)
                return perr(line, "expected 'key = value'");
            if (strncmp(p + kl, " = ", 3) != 0)
                return perr(line, "expected exactly 'key = value' (one space each side of '=')");
            char *v = p + kl + 3;
            p[kl] = '\0';
            if (*v == '\0')
                return perr(line, "empty value");
            if (v[0] == ' ' || v[strlen(v) - 1] == ' ')
                return perr(line, "leading or trailing space in value");
            if (!(seen & S_VERSION) && strcmp(p, "version") != 0)
                return perr(line, "the first setting must be 'version = 1'");
            if (apply(p, v, line, o, &seen) != 0)
                return -1;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    if (!(seen & S_VERSION))
        return perr(0, "missing 'version = 1'");
    if (!(seen & S_WORKSPACE))
        return perr(0, "missing required 'workspace'");

    /* Ambiguous or contradictory path rules. */
    for (size_t i = 0; i < o->nread; i++)
        if (path_listed(o->read_paths[i], o->read_paths, i) ||
            path_listed(o->read_paths[i], o->write_paths, o->nwrite) ||
            strcmp(o->read_paths[i], o->workspace) == 0)
            return perr(0, "a read path is duplicated or also writable");
    for (size_t i = 0; i < o->nwrite; i++)
        if (path_listed(o->write_paths[i], o->write_paths, i) ||
            strcmp(o->write_paths[i], o->workspace) == 0)
            return perr(0, "a write path is duplicated or equals the workspace");
    return 0;
}

struct devino {
    dev_t dev;
    ino_t ino;
};

static int add_root(struct devino *r, size_t *n, const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return errno == ENOENT ? 0 : -1; /* a missing root grants nothing */
    r[*n].dev = st.st_dev;
    r[*n].ino = st.st_ino;
    (*n)++;
    return 0;
}

static int is_root(const struct devino *r, size_t n, const struct stat *st)
{
    for (size_t i = 0; i < n; i++)
        if (r[i].dev == st->st_dev && r[i].ino == st->st_ino)
            return 1;
    return 0;
}

/* Walk from the object (self) and its directory (dirfd) up to "/" by inode. */
static int in_writable_at(int dirfd, const struct stat *self, const struct ag_policy *pol)
{
    struct devino roots[AG_MAX_PATHS + 1];
    size_t nroots = 0;
    if (add_root(roots, &nroots, pol->workspace) != 0)
        return -1;
    for (size_t i = 0; i < pol->nwrite && nroots < AG_MAX_PATHS + 1; i++)
        if (add_root(roots, &nroots, pol->write_paths[i]) != 0)
            return -1;
    if (is_root(roots, nroots, self))
        return 1;

    int cur = openat(dirfd, ".", O_PATH | O_DIRECTORY | O_CLOEXEC);
    for (int depth = 0; cur >= 0 && depth < PATH_MAX / 2; depth++) {
        struct stat st, up_st;
        if (fstat(cur, &st) != 0)
            break;
        if (is_root(roots, nroots, &st)) {
            close(cur);
            return 1;
        }
        int up = openat(cur, "..", O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (up < 0 || fstat(up, &up_st) != 0) {
            if (up >= 0)
                close(up);
            break;
        }
        close(cur);
        if (up_st.st_dev == st.st_dev && up_st.st_ino == st.st_ino) {
            close(up);
            return 0; /* reached "/" */
        }
        cur = up;
    }
    if (cur >= 0)
        close(cur);
    return -1;
}

/* Split a canonical absolute path into an O_PATH dirfd and the final name. */
static int open_parent(const char *path, const char **base)
{
    const char *slash = strrchr(path, '/');
    char dir[PATH_MAX];
    size_t dl = slash == path ? 1 : (size_t)(slash - path);
    if (!slash || dl >= sizeof dir) {
        errno = EINVAL;
        return -1;
    }
    memcpy(dir, path, dl);
    dir[dl] = '\0';
    *base = slash + 1;
    return open(dir, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

int ag_path_in_writable(const char *path, const struct ag_policy *pol)
{
    const char *base;
    int dfd = open_parent(path, &base);
    if (dfd < 0)
        return -1;
    struct stat st;
    int rc = fstatat(dfd, base, &st, AT_SYMLINK_NOFOLLOW) == 0 ? in_writable_at(dfd, &st, pol)
                                                              : -1;
    close(dfd);
    return rc;
}

int pf_load(const char *path, struct options *opts)
{
    if (!path_ok(path, 1))
        return perr(0, "--policy must be an absolute, normalized path to a file");
    char *real = realpath(path, NULL);
    if (!real) {
        ag_warnf("policy: cannot resolve --policy path: %s", strerror(errno));
        return -1;
    }
    int canonical = strcmp(real, path) == 0;
    free(real);
    if (!canonical)
        return perr(0, "--policy path must not go through symlinks (pass the canonical path)");

    const char *base;
    int dfd = open_parent(path, &base);
    int fd = dfd >= 0 ? openat(dfd, base, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) : -1;
    if (fd < 0) {
        ag_warnf("policy: cannot open --policy file: %s", strerror(errno));
        if (dfd >= 0)
            close(dfd);
        return -1;
    }
    struct stat st;
    const char *bad = NULL;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
        bad = "--policy must be a regular file";
    else if (st.st_mode & (S_IWGRP | S_IWOTH))
        bad = "policy file must not be group- or world-writable";
    else if (st.st_uid != geteuid() && st.st_uid != 0)
        bad = "policy file must be owned by the invoking user or root";
    else if (st.st_size > PF_MAX_BYTES)
        bad = "policy file too large (max 64 KiB)";
    size_t len = 0;
    while (!bad) {
        long r = read(fd, g_buf + len, sizeof g_buf - len);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0)
            bad = "cannot read policy file";
        else if (r == 0)
            break;
        else if ((len += (size_t)r) > PF_MAX_BYTES)
            bad = "policy file too large (max 64 KiB)";
    }
    close(fd);
    if (bad || parse(g_buf, len, opts) != 0) {
        close(dfd);
        return bad ? perr(0, bad) : -1;
    }

    /* Location check against the effective writable set of THIS run. */
    struct ag_policy pol;
    ag_policy_from_options(&pol, opts);
    int w = in_writable_at(dfd, &st, &pol);
    close(dfd);
    if (w != 0)
        return perr(0, w > 0 ? "policy file is inside a root the sandboxed target can write "
                               "(it could rewrite the policy for the next run); move it out"
                             : "cannot verify the policy file lies outside the writable roots");
    return 0;
}
