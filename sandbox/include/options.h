/* Command-line parsing for agentguard-run.
 *
 * Usage: agentguard-run [options] -- command [args...]
 * The target argv after "--" is passed to execvp unchanged; no shell is used.
 */
#ifndef AGENTGUARD_OPTIONS_H
#define AGENTGUARD_OPTIONS_H

#include <stddef.h>

#define AG_MAX_KEEP_FDS 64

struct options {
    char **argv;         /* target argv (NULL-terminated), points into argv[] */
    int argc;            /* target argc */
    long timeout_ms;     /* wall-clock deadline for the tree; 0 = none */
    int keep_fds[AG_MAX_KEEP_FDS];
    size_t nkeep;
    int degraded;        /* AG_MODE_DEGRADED when set, else strict */
    int verbose;         /* print negotiation + applied layers to stderr */
    int print_status;    /* print the layer table and exit without running */
    int json;            /* machine-readable status output */
    int show_help;
    int show_version;
};

/* Parse argv into opts. Returns 0 on success; -1 on a usage error (message
 * already printed). On --help/--version, sets the flag and returns 0 with no
 * target required. */
int options_parse(int argc, char **argv, struct options *opts);

void options_usage(const char *prog);

#endif
