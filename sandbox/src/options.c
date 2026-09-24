#include "options.h"
#include "util.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void options_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options] -- command [args...]\n"
        "\n"
        "Run command inside AgentGuard's sandbox. The target argv after '--'\n"
        "is executed directly (no shell).\n"
        "\n"
        "Options:\n"
        "  --timeout SECONDS   Terminate the process tree after SECONDS (float ok).\n"
        "  --keep-fd N         Preserve inherited file descriptor N in the target\n"
        "                      (besides stdin/stdout/stderr). May repeat.\n"
        "  --version           Print version and exit.\n"
        "  --help              Print this help and exit.\n",
        prog);
}

/* Parse a non-negative integer fd in [0, INT_MAX]. Returns -1 on error. */
static int parse_fd(const char *s)
{
    if (!s || !*s)
        return -1;
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || *end != '\0' || v < 0 || v > INT_MAX)
        return -1;
    return (int)v;
}

/* Parse seconds (accepts decimals) into milliseconds. Returns -1 on error. */
static long parse_timeout_ms(const char *s)
{
    if (!s || !*s)
        return -1;
    char *end = NULL;
    errno = 0;
    double sec = strtod(s, &end);
    if (errno != 0 || *end != '\0' || sec < 0 || sec > 1e7)
        return -1;
    return (long)(sec * 1000.0);
}

int options_parse(int argc, char **argv, struct options *opts)
{
    memset(opts, 0, sizeof *opts);
    opts->timeout_ms = 0;

    int i = 1;
    for (; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "--") == 0) {
            i++;
            break;
        }
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            opts->show_help = 1;
            return 0;
        }
        if (strcmp(arg, "--version") == 0) {
            opts->show_version = 1;
            return 0;
        }
        if (strcmp(arg, "--timeout") == 0) {
            if (++i >= argc) {
                ag_warnf("--timeout requires an argument");
                return -1;
            }
            opts->timeout_ms = parse_timeout_ms(argv[i]);
            if (opts->timeout_ms < 0) {
                ag_warnf("invalid --timeout value: %s", argv[i]);
                return -1;
            }
            continue;
        }
        if (strcmp(arg, "--keep-fd") == 0) {
            if (++i >= argc) {
                ag_warnf("--keep-fd requires an argument");
                return -1;
            }
            int fd = parse_fd(argv[i]);
            if (fd < 0) {
                ag_warnf("invalid --keep-fd value: %s", argv[i]);
                return -1;
            }
            if (fd <= 2) {
                /* stdio is always preserved; ignore rather than error. */
                continue;
            }
            if (opts->nkeep >= AG_MAX_KEEP_FDS) {
                ag_warnf("too many --keep-fd options (max %d)", AG_MAX_KEEP_FDS);
                return -1;
            }
            opts->keep_fds[opts->nkeep++] = fd;
            continue;
        }
        if (arg[0] == '-' && arg[1] != '\0') {
            ag_warnf("unknown option: %s", arg);
            return -1;
        }
        /* A bare word before '--' is a usage error: require the separator so the
         * boundary between our options and the target is always explicit. */
        ag_warnf("expected '--' before the command (got '%s')", arg);
        return -1;
    }

    if (i >= argc) {
        ag_warnf("no command given after '--'");
        return -1;
    }
    opts->argv = &argv[i];
    opts->argc = argc - i;
    return 0;
}
