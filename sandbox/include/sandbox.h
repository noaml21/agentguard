/* Enforcement-layer negotiation and the fail-closed setup contract.
 *
 * Capability detection is not enforcement. For every layer we track three
 * distinct facts:
 *   AVAILABLE  - the running kernel supports it (probed in the parent);
 *   REQUESTED  - the selected policy/mode wants it;
 *   APPLIED    - the child installed it successfully (reported back before exec).
 *
 * Contract: the target is executed only if every REQUIRED+REQUESTED layer is
 * APPLIED. In strict mode a required layer that is unavailable or fails to apply
 * refuses the run (the target never execs). Degraded mode must be requested
 * explicitly and reports exactly which guarantees are missing; it never silently
 * drops a layer.
 */
#ifndef AGENTGUARD_SANDBOX_H
#define AGENTGUARD_SANDBOX_H

#include <stdint.h>

#include "policy.h"

enum ag_layer {
    AG_LAYER_NO_NEW_PRIVS = 0, /* must stay first: prerequisite for the rest */
    AG_LAYER_LANDLOCK_FS,      /* filesystem enforcement (Phase 4) */
    AG_LAYER_SECCOMP,          /* syscall deny-list; must stay last-applied (Phase 5) */
    /* Phase 6+ append network/resource layers */
    AG_LAYER_COUNT
};

enum ag_mode {
    AG_MODE_STRICT = 0, /* all required layers, or refuse */
    AG_MODE_DEGRADED,   /* explicitly requested; run with missing layers reported */
};

/* Report written by the child over the report pipe before exec. */
enum ag_report_tag {
    AG_REPORT_SETUP_OK = 1,   /* setup finished; applied_mask valid; about to exec */
    AG_REPORT_SETUP_FAIL = 2, /* a layer failed to apply */
    AG_REPORT_EXEC_FAIL = 3,  /* execvp failed after successful setup */
};

struct ag_report {
    int32_t tag;           /* enum ag_report_tag */
    int32_t layer;         /* enum ag_layer for SETUP_FAIL, else -1 */
    int32_t err;           /* errno for FAIL/EXEC_FAIL, else 0 */
    uint32_t applied_mask; /* bitmask of applied layers (OK/EXEC_FAIL) */
};

struct ag_negotiation {
    enum ag_mode mode;
    uint32_t available_mask;
    uint32_t requested_mask;
    uint32_t required_mask; /* subset of requested that must apply */
    uint32_t missing_mask;  /* required but unavailable (degraded reporting) */
};

#define AG_LAYER_BIT(layer) (1u << (layer))

const char *ag_layer_name(enum ag_layer layer);

/* Parent side: probe availability, resolve requested/required from mode, and
 * detect required-but-unavailable layers. Returns 0 on success. In strict mode,
 * if any required layer is unavailable, fills missing_mask and returns -1 (the
 * caller must refuse before fork). In degraded mode, unavailable required layers
 * are moved out of requested into missing_mask and 0 is returned. */
int ag_negotiate(enum ag_mode mode, struct ag_negotiation *neg);

/* Child side: apply every requested layer in order, recording applied ones.
 * Layers are applied in enum order, which encodes the required setup sequence
 * (no_new_privs before Landlock/seccomp). pol supplies filesystem/network rules.
 * On the first failure, writes AG_REPORT_SETUP_FAIL and returns -1 (caller must
 * _exit). On success, writes AG_REPORT_SETUP_OK with the applied mask and
 * returns 0 (caller proceeds to exec). report_fd is the write end of the pipe. */
int ag_apply_layers(const struct ag_negotiation *neg, const struct ag_policy *pol,
                    int report_fd);

/* Human-readable status table to the given stream. applied_mask may be 0 if not
 * yet known (pre-run). */
void ag_print_status(int fd, const struct ag_negotiation *neg, uint32_t applied_mask,
                     int as_json);

#endif
