/* Policy file (Phase 8): a narrow, strict, line-based format.
 *
 *   # comment lines and empty lines are ignored
 *   version = 1                      (required, must be the first setting)
 *   workspace = /abs/path            (required, once)
 *   read = /abs/path                 (repeatable)
 *   write = /abs/path                (repeatable)
 *   default-reads = yes|no           (once; default yes)
 *   net = none|all                   (once; default none)
 *   timeout = SECONDS                (once; digits with at most one '.')
 *   max-file-size = BYTES            (once)
 *   max-open-files = N               (once; >= 16)
 *
 * Exactly "key = value" per line: one space each side of '=', value taken
 * verbatim to end of line (so paths may contain spaces), no quoting, no
 * escapes, no expansion, no includes. ASCII only; tabs, CR and other control
 * bytes are errors. Unknown or duplicate keys, empty values, unnormalized or
 * relative paths, and contradictory path rules are errors. Bounded: 64 KiB,
 * 1024 lines, AG_MAX_PATHS paths per list, PATH_MAX per path.
 *
 * The policy fills the same struct options the CLI does (one internal
 * representation, one set of value parsers). It may not be combined with the
 * CLI options it covers.
 */
#ifndef AGENTGUARD_POLICYFILE_H
#define AGENTGUARD_POLICYFILE_H

#include "options.h"
#include "policy.h"

/* Parent, before fork: open the policy at path (absolute, canonical, no
 * symlinks) without following links, verify it is a regular file owned by us
 * or root and not group/world-writable, parse it strictly into opts, then
 * refuse it if the file or any ancestor directory is a root the sandboxed
 * target could write (so a run cannot rewrite the next run's policy). Returns 0,
 * or -1 after printing one bounded, content-free error. */
int pf_load(const char *path, struct options *opts);

/* 1 if the file at canonical path, or any ancestor directory, is one of pol's
 * writable roots (compared by device+inode, not by string); 0 if not; -1 if it
 * cannot be determined. */
int ag_path_in_writable(const char *path, const struct ag_policy *pol);

#endif
