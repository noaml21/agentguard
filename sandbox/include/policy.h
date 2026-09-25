/* Sandbox policy: what the target is allowed to touch.
 *
 * Phase 4 builds this from CLI options; Phase 8 adds a policy-file parser that
 * fills the same struct. Kept deliberately small and explicit.
 */
#ifndef AGENTGUARD_POLICY_H
#define AGENTGUARD_POLICY_H

#include <stddef.h>

#define AG_MAX_PATHS 64

/* Network posture. The measured kernel gives Landlock TCP restriction by PORT
 * only (no destination filtering) and no UDP/namespace isolation, so we do not
 * pretend to offer a destination allowlist. The honest, strong primitive is a
 * seccomp socket() address-family filter: all-or-nothing IP networking. */
enum ag_net_mode {
    AG_NET_NONE = 0, /* socket() only for AF_UNIX/AF_NETLINK: no TCP/UDP/raw IP */
    AG_NET_ALL,      /* no network restriction (intentional egress, e.g. for claude) */
};

struct ag_policy {
    enum ag_net_mode net_mode;
    int cgroup_join_err;                /* 0 if the child joined the owned cgroup, else errno */
    const char *workspace;              /* writable root (rw+create+remove) */
    const char *read_paths[AG_MAX_PATHS];
    size_t nread;
    const char *write_paths[AG_MAX_PATHS]; /* extra writable roots beyond workspace */
    size_t nwrite;
    int no_default_reads;               /* if set, do not add the system read set */
};

/* Fill read_paths with the default system read/exec locations needed to run
 * ordinary programs (/usr, /bin, /lib*, /etc, /proc, /sys, /dev). Appends to any
 * already present; respects AG_MAX_PATHS. */
void ag_policy_add_default_reads(struct ag_policy *pol);

/* Add default writable scratch locations (currently /tmp), which most dev tools
 * (compilers, git) require. /tmp is a shared same-UID surface -- documented as a
 * known broadening, opt out with --no-default-reads. Appends; bounded. */
void ag_policy_add_default_writes(struct ag_policy *pol);

#endif
