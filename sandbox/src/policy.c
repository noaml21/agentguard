#include "policy.h"

/* Default read/execute locations an ordinary program needs to run. Non-existent
 * entries are skipped when rules are added, so this list is safe across distros.
 * Deliberately excludes the user's home directory and credential locations --
 * only the workspace under $HOME becomes accessible, via --workspace. */
static const char *kDefaultReads[] = {
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32",
    "/etc", "/proc", "/sys", "/dev",
    "/run/systemd/resolve", /* resolv.conf symlink target on systemd hosts */
};

void ag_policy_add_default_reads(struct ag_policy *pol)
{
    if (pol->no_default_reads)
        return;
    for (size_t i = 0; i < sizeof(kDefaultReads) / sizeof(kDefaultReads[0]); i++) {
        if (pol->nread >= AG_MAX_PATHS)
            return;
        pol->read_paths[pol->nread++] = kDefaultReads[i];
    }
}

void ag_policy_add_default_writes(struct ag_policy *pol)
{
    if (pol->no_default_reads)
        return;
    if (pol->nwrite >= AG_MAX_PATHS)
        return;
    pol->write_paths[pol->nwrite++] = "/tmp";
}
