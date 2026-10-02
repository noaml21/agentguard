#define _GNU_SOURCE
#include "cgroup.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <time.h>
#include <unistd.h>

#define AG_CGROUP_ROOT "/sys/fs/cgroup"
#define AG_CGROUP2_MAGIC 0x63677270 /* CGROUP2_SUPER_MAGIC */

/* Absolute path of the calling process's cgroup v2 directory, from the "0::"
 * line of /proc/self/cgroup. Returns 0 or -1. */
static int current_cgroup_dir(char *buf, size_t len)
{
    struct statfs sfs;
    if (statfs(AG_CGROUP_ROOT, &sfs) != 0 || (unsigned long)sfs.f_type != AG_CGROUP2_MAGIC) {
        errno = ENOTSUP;
        return -1;
    }
    FILE *f = fopen("/proc/self/cgroup", "re");
    if (!f)
        return -1;
    char line[PATH_MAX];
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "0::", 3) == 0) {
            line[strcspn(line, "\n")] = '\0';
            int n = snprintf(buf, len, "%s%s", AG_CGROUP_ROOT, line + 3);
            found = n > 0 && (size_t)n < len;
            break;
        }
    }
    fclose(f);
    if (!found) {
        errno = ENOENT;
        return -1;
    }
    return 0;
}

int cg_available(void)
{
    char dir[PATH_MAX];
    if (current_cgroup_dir(dir, sizeof dir) != 0)
        return 0;
    int dfd = open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0)
        return 0;
    /* Migrating a process needs write access to cgroup.procs of the common
     * ancestor of source and destination -- i.e. this directory. */
    int ok = faccessat(dfd, ".", W_OK, AT_EACCESS) == 0 &&
             faccessat(dfd, "cgroup.procs", W_OK, AT_EACCESS) == 0 &&
             faccessat(dfd, "cgroup.kill", F_OK, 0) == 0;
    close(dfd);
    return ok;
}

int cg_create(struct ag_cgroup *cg)
{
    cg->parent_fd = cg->procs_fd = cg->kill_fd = -1;
    cg->name[0] = '\0';

    char dir[PATH_MAX];
    if (current_cgroup_dir(dir, sizeof dir) != 0)
        return -1;
    int pfd = open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (pfd < 0)
        return -1;
    snprintf(cg->name, sizeof cg->name, "agentguard-run.%ld", (long)getpid());
    /* mkdirat fails with EEXIST rather than adopting a directory someone else
     * made, so we only ever manage a cgroup this run created. */
    if (mkdirat(pfd, cg->name, 0755) != 0) {
        int err = errno;
        close(pfd);
        cg->name[0] = '\0';
        errno = err;
        return -1;
    }
    char path[sizeof cg->name + 32];
    snprintf(path, sizeof path, "%s/cgroup.procs", cg->name);
    int procs = openat(pfd, path, O_WRONLY | O_CLOEXEC);
    snprintf(path, sizeof path, "%s/cgroup.kill", cg->name);
    int kill = openat(pfd, path, O_WRONLY | O_CLOEXEC);
    if (procs < 0 || kill < 0) {
        int err = errno;
        if (procs >= 0)
            close(procs);
        if (kill >= 0)
            close(kill);
        (void)unlinkat(pfd, cg->name, AT_REMOVEDIR);
        close(pfd);
        cg->name[0] = '\0';
        errno = err;
        return -1;
    }
    cg->parent_fd = pfd;
    cg->procs_fd = procs;
    cg->kill_fd = kill;
    return 0;
}

int cg_join(int procs_fd)
{
    if (procs_fd < 0) {
        errno = EBADF;
        return -1;
    }
    /* "0" means the writing process itself. */
    return ag_write_all(procs_fd, "0", 1);
}

void cg_kill(const struct ag_cgroup *cg)
{
    if (cg->kill_fd >= 0 && ag_write_all(cg->kill_fd, "1", 1) != 0)
        ag_warn_errno("cgroup.kill");
}

void cg_destroy(struct ag_cgroup *cg)
{
    if (cg->procs_fd >= 0)
        close(cg->procs_fd);
    if (cg->kill_fd >= 0)
        close(cg->kill_fd);
    if (cg->parent_fd >= 0 && cg->name[0]) {
        /* cgroup.kill is asynchronous with respect to the cgroup emptying; the
         * caller has reaped the tree, but allow a short settle before giving up. */
        for (int i = 0; i < 100; i++) {
            if (unlinkat(cg->parent_fd, cg->name, AT_REMOVEDIR) == 0 || errno != EBUSY)
                break;
            struct timespec nap = {0, 10 * 1000 * 1000};
            nanosleep(&nap, NULL);
        }
    }
    if (cg->parent_fd >= 0)
        close(cg->parent_fd);
    cg->parent_fd = cg->procs_fd = cg->kill_fd = -1;
    cg->name[0] = '\0';
}
