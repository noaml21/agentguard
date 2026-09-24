/* Sandbox policy: what the target is allowed to touch.
 *
 * Phase 4 builds this from CLI options; Phase 8 adds a policy-file parser that
 * fills the same struct. Kept deliberately small and explicit.
 */
#ifndef AGENTGUARD_POLICY_H
#define AGENTGUARD_POLICY_H

#include <stddef.h>

#define AG_MAX_PATHS 64

struct ag_policy {
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

#endif
