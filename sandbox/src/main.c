#define _GNU_SOURCE
#include "lifecycle.h"
#include "options.h"
#include "policyfile.h"
#include "sandbox.h"
#include "util.h"

#include <limits.h>
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

    /* Policy file: validated completely in the parent before anything forks. It
     * is the single source of the settings it covers -- no CLI merge. */
    if (opts.policy_path) {
        if (opts.policy_conflict) {
            ag_warnf("%s cannot be combined with --policy (the policy file is the single "
                     "source of that setting)", opts.policy_conflict);
            return AG_EXIT_SETUP_FAILURE;
        }
        if (pf_load(opts.policy_path, &opts) != 0)
            return AG_EXIT_SETUP_FAILURE;
    }

    /* Control-plane integrity: could the target replace this runner binary for a
     * future run? Refused in policy mode, reported otherwise. */
    struct ag_policy effective;
    ag_policy_from_options(&effective, &opts);
    char exe[PATH_MAX];
    long exe_len = readlink("/proc/self/exe", exe, sizeof exe - 1);
    int runner_writable = -1;
    if (exe_len > 0) {
        exe[exe_len] = '\0';
        runner_writable = ag_path_in_writable(exe, &effective);
    }
    if (opts.policy_path && runner_writable != 0) {
        ag_warnf("policy mode: the agentguard-run binary is %s a root the sandboxed target "
                 "can write (it could replace the runner for the next run); install it "
                 "outside the workspace and writable paths",
                 runner_writable > 0 ? "inside" : "not verifiably outside");
        return AG_EXIT_SETUP_FAILURE;
    }

    enum ag_mode mode = opts.degraded ? AG_MODE_DEGRADED : AG_MODE_STRICT;
    struct ag_negotiation neg;
    int neg_rc = ag_negotiate(mode, opts.net_mode, &neg);
    neg.timeout_ms = opts.timeout_ms;
    neg.max_fsize = opts.max_fsize;
    neg.max_nofile = opts.max_nofile;
    neg.policy_used = opts.policy_path != NULL;
    neg.runner_writable = runner_writable;

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

    /* Degraded mode never hides a lost network guarantee, verbose or not. */
    if (!ag_net_enforced(&neg, neg.requested_mask))
        ag_warnf("degraded: --net none is NOT enforced (seccomp unavailable); "
                 "IP networking is allowed for this run");

    return lifecycle_run(&opts, &neg);
}
