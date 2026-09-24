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
    int show_help;
    int show_version;
};

/* Parse argv into opts. Returns 0 on success; -1 on a usage error (message
 * already printed). On --help/--version, sets the flag and returns 0 with no
 * target required. */
int options_parse(int argc, char **argv, struct options *opts);

void options_usage(const char *prog);

#endif
