/* Thin wrapper over the Landlock LSM: runtime ABI detection and applying a
 * filesystem ruleset derived from the policy.
 *
 * Landlock is default-deny per handled access right: once a right is "handled",
 * access is allowed only where an explicit rule grants it. Rights the running
 * ABI does not support are simply not handled (feature-by-feature degradation).
 * Rules bind to an opened inode (O_PATH fd), so enforcement applies to the same
 * object that was validated -- a later symlink/rename cannot redirect it.
 */
#ifndef AGENTGUARD_LANDLOCK_H
#define AGENTGUARD_LANDLOCK_H

#include "policy.h"

/* Returns the running Landlock ABI version (>=1), 0 if Landlock is present but
 * reports version 0, or -1 if unavailable (errno set). Read-only. */
int ll_abi(void);

/* Child side: build and enforce the filesystem ruleset for pol. Must be called
 * after PR_SET_NO_NEW_PRIVS. Returns 0 on success, -1 on failure (errno set).
 * On success the calling thread and all its future children are restricted. */
int ll_restrict_fs(const struct ag_policy *pol);

#endif
