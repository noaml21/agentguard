/* cgroup v2 kill tier (Phase 7).
 *
 * When the runner's current cgroup is a writable (delegated) cgroup v2 directory,
 * the parent creates an owned child cgroup "agentguard-run.<pid>" under it, the
 * child joins it before exec, and teardown writes cgroup.kill so every process
 * in the tree dies -- including descendants that left the process group with
 * setsid()/setpgid(). The directory is removed afterwards.
 *
 * Scope, deliberately narrow: only the owned child cgroup is ever written. No
 * controllers are enabled and no other process is moved, so aggregate limits
 * (pids.max, memory.max) are NOT provided: enabling them would require writing
 * the parent's cgroup.subtree_control, which we do not own and which the cgroup
 * v2 no-internal-process rule rejects while the parent holds other processes.
 */
#ifndef AGENTGUARD_CGROUP_H
#define AGENTGUARD_CGROUP_H

#include <limits.h>

struct ag_cgroup {
    int parent_fd;  /* O_PATH|O_DIRECTORY fd of the runner's current cgroup, or -1 */
    int procs_fd;   /* O_WRONLY fd of <owned>/cgroup.procs (the child writes "0"), or -1 */
    int kill_fd;    /* O_WRONLY fd of <owned>/cgroup.kill, or -1 */
    char name[64];  /* owned directory name under parent_fd */
};

/* 1 if cgroup v2 is mounted at /sys/fs/cgroup, the current cgroup directory and
 * its cgroup.procs are writable by us, and cgroup.kill exists (kernel >= 5.14). */
int cg_available(void);

/* Parent: create and open the owned child cgroup. Returns 0, or -1 (errno set)
 * with every fd in *cg left at -1. */
int cg_create(struct ag_cgroup *cg);

/* Child: move the calling process into the owned cgroup. */
int cg_join(int procs_fd);

/* Parent: kill every process in the owned cgroup (no-op if not created). */
void cg_kill(const struct ag_cgroup *cg);

/* Parent: close fds and remove the owned directory (must be empty). */
void cg_destroy(struct ag_cgroup *cg);

#endif
