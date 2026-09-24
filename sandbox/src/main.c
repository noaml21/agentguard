#define _GNU_SOURCE
#include "lifecycle.h"
#include "options.h"
#include "sandbox.h"
#include "util.h"

#include <stdio.h>
#include <unistd.h>

#define AGENTGUARD_RUN_VERSION "0.2.0-phase2"

int main(int argc, char **argv)
{
    struct options opts;
    if (options_parse(argc, argv, &opts) != 0) {
        options_usage(argv[0]);
        return AG_EXIT_SETUP_FAILURE;
    }
    if (opts.show_help) {
        options_usage(argv[0]);
        return 0;
    }
    if (opts.show_version) {
        printf("agentguard-run %s\n", AGENTGUARD_RUN_VERSION);
        return 0;
    }

    /* Privilege model: refuse to run as root. As root, Landlock and seccomp
     * still apply but root retains capabilities that let it escape the intended
     * guarantees, so every documented claim would be false. AgentGuard is never
     * setuid and offers no root override in Core. */
    if (geteuid() == 0) {
        ag_warnf("refusing to run as root (EUID 0); run as an unprivileged user");
        return AG_EXIT_SETUP_FAILURE;
    }

    enum ag_mode mode = opts.degraded ? AG_MODE_DEGRADED : AG_MODE_STRICT;
    struct ag_negotiation neg;
    int neg_rc = ag_negotiate(mode, &neg);

    if (opts.print_status) {
        ag_print_status(1, &neg, 0, opts.json);
        return 0;
    }

    /* Strict mode: a required layer unavailable on this kernel refuses the run
     * before fork -- the target never executes (fail-closed, no silent downgrade). */
    if (neg_rc != 0) {
        ag_warnf("strict mode: required enforcement layer(s) unavailable on this "
                 "kernel; refusing to run. Use --status to inspect, or --degraded "
                 "to run with reduced guarantees.");
        ag_print_status(2, &neg, 0, opts.json);
        return AG_EXIT_SETUP_FAILURE;
    }

    if (opts.verbose && neg.missing_mask)
        ag_print_status(2, &neg, 0, opts.json);

    return lifecycle_run(&opts, &neg);
}
