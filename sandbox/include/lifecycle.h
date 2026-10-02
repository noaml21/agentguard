/* Process lifecycle: fork/exec the target, own its process group and any
 * reparented descendants, forward signals, enforce the deadline, propagate the
 * exit status, and reap the whole tree on exit.
 */
#ifndef AGENTGUARD_LIFECYCLE_H
#define AGENTGUARD_LIFECYCLE_H

#include "options.h"
#include "sandbox.h"

/* Fork, set up the child (process group, FD sanitation, enforcement layers),
 * exec the target, and supervise it. neg is the resolved negotiation from
 * ag_negotiate(); the child applies its requested layers and the target execs
 * only if setup succeeds. Returns the exit code the runner should use:
 *  - the target's own exit code, or 128+signo if it died from a signal;
 *  - AG_EXIT_TIMEOUT if the deadline fired;
 *  - AG_EXIT_EXEC_FAILURE if the target could not be executed;
 *  - AG_EXIT_SETUP_FAILURE if a required layer failed to apply (target refused).
 */
int lifecycle_run(const struct options *opts, const struct ag_negotiation *neg);

#endif
