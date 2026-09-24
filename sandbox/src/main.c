#define _GNU_SOURCE
#include "lifecycle.h"
#include "options.h"
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

    return lifecycle_run(&opts);
}
