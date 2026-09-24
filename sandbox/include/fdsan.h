/* File-descriptor sanitation.
 *
 * A sandbox is useless if the target inherits authority through an already-open
 * descriptor (an open file, socket, or pipe to something outside the sandbox).
 * Before exec we close every descriptor except the ones we intentionally allow.
 */
#ifndef AGENTGUARD_FDSAN_H
#define AGENTGUARD_FDSAN_H

#include <stddef.h>

struct fdsan_policy {
    const int *keep; /* user descriptors to preserve across exec (besides 0,1,2) */
    size_t nkeep;
    int report_fd;   /* runner->parent report pipe; kept until exec, then CLOEXEC */
};

/* Apply the policy in the just-forked child:
 *  - descriptors 0,1,2 and every fd in keep[] survive exec (FD_CLOEXEC cleared);
 *  - report_fd is set FD_CLOEXEC (closes atomically at execve, signalling success);
 *  - every other descriptor is closed.
 * Prefers close_range(); falls back to iterating /proc/self/fd.
 * Returns 0 on success, -1 on error (errno set). Async-signal-safe enough for
 * the post-fork context: uses only close_range/fcntl/open/read/close. */
int fdsan_apply(const struct fdsan_policy *policy);

#endif
