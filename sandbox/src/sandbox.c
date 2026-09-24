#define _GNU_SOURCE
#include "sandbox.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

/* ---- Individual layers ------------------------------------------------- */

static int probe_no_new_privs(void)
{
    /* Readable everywhere we care about; PR_GET returns 0/1, -1 on unsupported. */
    return prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) >= 0;
}

static int apply_no_new_privs(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    return prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 ? 0 : (errno = EPERM, -1);
}

struct layer_def {
    const char *name;
    int (*probe)(void);
    int (*apply)(void);
    int required_by_default;
};

static const struct layer_def kLayers[AG_LAYER_COUNT] = {
    [AG_LAYER_NO_NEW_PRIVS] = {
        .name = "no_new_privs",
        .probe = probe_no_new_privs,
        .apply = apply_no_new_privs,
        .required_by_default = 1,
    },
};

const char *ag_layer_name(enum ag_layer layer)
{
    if (layer < 0 || layer >= AG_LAYER_COUNT)
        return "unknown";
    return kLayers[layer].name;
}

/* ---- Test seams --------------------------------------------------------
 * These environment variables exist only to test the fail-closed contract on
 * any kernel (a layer's real availability is kernel-dependent). They take a
 * comma-separated list of layer names. Documented in docs/process/BUILD_LOG.md.
 */
static int env_lists_layer(const char *var, const char *name)
{
    const char *v = getenv(var);
    if (!v || !*v)
        return 0;
    size_t nlen = strlen(name);
    const char *p = v;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t seg = comma ? (size_t)(comma - p) : strlen(p);
        if (seg == nlen && strncmp(p, name, nlen) == 0)
            return 1;
        if (!comma)
            break;
        p = comma + 1;
    }
    return 0;
}

/* ---- Negotiation (parent) ---------------------------------------------- */

int ag_negotiate(enum ag_mode mode, struct ag_negotiation *neg)
{
    memset(neg, 0, sizeof *neg);
    neg->mode = mode;

    for (int i = 0; i < AG_LAYER_COUNT; i++) {
        uint32_t bit = AG_LAYER_BIT(i);
        int available = kLayers[i].probe && kLayers[i].probe();
        if (env_lists_layer("AGENTGUARD_TEST_UNAVAIL", kLayers[i].name))
            available = 0;
        if (available)
            neg->available_mask |= bit;
        if (kLayers[i].required_by_default) {
            neg->requested_mask |= bit;
            neg->required_mask |= bit;
        }
    }

    neg->missing_mask = neg->required_mask & ~neg->available_mask;
    if (neg->missing_mask) {
        if (mode == AG_MODE_STRICT)
            return -1; /* caller refuses before fork */
        /* Degraded: drop the unavailable layers from what we will apply, but
         * keep them recorded in missing_mask so we report the lost guarantees. */
        neg->requested_mask &= ~neg->missing_mask;
        neg->required_mask &= ~neg->missing_mask;
    }
    return 0;
}

/* ---- Apply (child) ------------------------------------------------------ */

int ag_apply_layers(const struct ag_negotiation *neg, int report_fd)
{
    struct ag_report rep = {.tag = 0, .layer = -1, .err = 0, .applied_mask = 0};

    for (int i = 0; i < AG_LAYER_COUNT; i++) {
        uint32_t bit = AG_LAYER_BIT(i);
        if (!(neg->requested_mask & bit))
            continue;
        int fail = env_lists_layer("AGENTGUARD_TEST_FAIL", kLayers[i].name);
        int rc;
        if (fail) {
            errno = EPERM;
            rc = -1;
        } else {
            rc = kLayers[i].apply ? kLayers[i].apply() : (errno = ENOSYS, -1);
        }
        if (rc != 0) {
            rep.tag = AG_REPORT_SETUP_FAIL;
            rep.layer = i;
            rep.err = errno;
            rep.applied_mask = rep.applied_mask; /* what applied before failure */
            (void)ag_write_all(report_fd, &rep, sizeof rep);
            return -1;
        }
        rep.applied_mask |= bit;
    }

    rep.tag = AG_REPORT_SETUP_OK;
    rep.layer = -1;
    rep.err = 0;
    (void)ag_write_all(report_fd, &rep, sizeof rep);
    return 0;
}

/* ---- Status ------------------------------------------------------------ */

static const char *layer_state(const struct ag_negotiation *neg, uint32_t applied,
                               int i)
{
    uint32_t bit = AG_LAYER_BIT(i);
    if (applied & bit)
        return "applied";
    if (neg->missing_mask & bit)
        return "missing";
    if (!(neg->available_mask & bit))
        return "unavailable";
    if (neg->requested_mask & bit)
        return "requested";
    return "off";
}

void ag_print_status(int fd, const struct ag_negotiation *neg, uint32_t applied,
                     int as_json)
{
    FILE *out = (fd == 2) ? stderr : stdout;
    if (as_json) {
        fprintf(out, "{\"mode\":\"%s\",\"layers\":[",
                neg->mode == AG_MODE_STRICT ? "strict" : "degraded");
        for (int i = 0; i < AG_LAYER_COUNT; i++) {
            uint32_t bit = AG_LAYER_BIT(i);
            fprintf(out,
                    "%s{\"name\":\"%s\",\"available\":%s,\"requested\":%s,"
                    "\"required\":%s,\"applied\":%s}",
                    i ? "," : "", kLayers[i].name,
                    (neg->available_mask & bit) ? "true" : "false",
                    (neg->requested_mask & bit) ? "true" : "false",
                    (neg->required_mask & bit) ? "true" : "false",
                    (applied & bit) ? "true" : "false");
        }
        fprintf(out, "]}\n");
        return;
    }
    fprintf(out, "AgentGuard sandbox status (mode=%s)\n",
            neg->mode == AG_MODE_STRICT ? "strict" : "degraded");
    fprintf(out, "  %-16s %-12s %s\n", "layer", "state", "required");
    for (int i = 0; i < AG_LAYER_COUNT; i++) {
        uint32_t bit = AG_LAYER_BIT(i);
        fprintf(out, "  %-16s %-12s %s\n", kLayers[i].name,
                layer_state(neg, applied, i),
                (neg->required_mask & bit) ? "yes" : "no");
    }
    if (neg->missing_mask) {
        fprintf(out, "  WARNING: missing required layers -> guarantees reduced\n");
    }
}
