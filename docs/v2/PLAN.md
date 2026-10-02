# AgentGuard V2 Plan

Fixed, ordered roadmap. Volatile progress lives only in `docs/process/BUILD_STATE.md`.
A phase is complete only when its gate is met and recorded in `docs/process/BUILD_LOG.md`.

## Core phases

| # | Phase | Work units | Completion gate |
|---|---|---|---|
| 0 | Environment capability audit | 0.1 host/kernel probe (`scripts/capability_audit.sh`, `sandbox/probe/capprobe.c`); 0.2 record results in ARCHITECTURE | Probe runs unprivileged; results recorded; guarantees designed around measured ABI |
| 1 | V1 adversarial baseline | 1.1 structured case corpus (`redteam/cases/*.json`); 1.2 effect oracle + V1 driver via hook-chain harness; 1.3 JSON + table report | Corpus runs deterministically on disposable fixtures only; results committed |
| 2 | C runner, lifecycle, FD sanitation, TTY | 2.1 CLI + execvp + root refusal; 2.2 FD policy (close_range + /proc fallback); 2.3 lifecycle (subreaper, pgid, signal forwarding, timeout, exit status); 2.4 TTY/foreground pgrp handling | Integration tests for fds, signals, exit codes, timeout, descendant reaping pass; `-Wall -Wextra -Werror`; ASan/UBSan build passes tests |
| 3 | Fail-closed setup contract | 3.1 layer negotiation (available/requested/applied); 3.2 setup report pipe child→parent; 3.3 strict vs explicit degraded mode; 3.4 status output | Tests: unavailable-required refuses; setup failure refuses; degraded run lists missing guarantees; no silent downgrade |
| 4 | Landlock filesystem | 4.1 ruleset from policy; 4.2 path-fd rules opened pre-restrict; 4.3 tests (direct, traversal, symlink, rename, replacement, interpreters, descendants) | Denied/permitted matrix passes against the kernel |
| 5 | seccomp-BPF + no_new_privs | 5.1 design comparison recorded; 5.2 filter + per-rule rationale; 5.3 allow/deny + inheritance tests | Deterministic tests; arch check; every rule documented |
| 6 | Network policy modes | 6.1 mode definitions; 6.2 Landlock TCP port rules + seccomp socket family filter; 6.3 tests per mode | Denied/allowed network behavior verified per mode; claims match kernel |
| 7 | Resource limits | 7.1 rlimits with honest semantics; 7.2 wall-clock deadline; 7.3 delegated cgroup v2 when safely available, else reported fallback | Tests for deadline, rlimit application, cgroup kill (host-only tier) |
| 8 | Policy format + integrity | 8.1 narrow format + strict parser; 8.2 malformed-input tests; 8.3 self-modification defense (policy outside writable set, opened pre-restrict) | Parser tests pass; sandboxed process cannot alter next run's policy/binary |
| 9 | Host IPC / same-UID surface | 9.1 surface inventory + decisions; 9.2 fixtures (signals, ptrace, abstract/pathname unix sockets, inherited fds) | Each surface is Core / non-goal / degraded, with fixture evidence |
| 10 | V1 + V2 integration | 10.1 `agentguard-run -- claude` workflow; 10.2 docs separating UX guardrails vs enforcement; 10.3 dev-command tests under sandbox | Common dev commands work inside sandbox; descendants covered |
| 11 | Adversarial V1 vs V2 comparison | 11.1 replay Phase 1 corpus under V2; 11.2 expanded cases; 11.3 results artifact | Reproducible matrix, failures kept visible |
| 12 | CI + docs | 12.1 CI tiers (unit / integration / kernel-feature / host-only) with explicit skip reasons; 12.2 README end state + diagram + demo | CI green with truthful skips; README complete |

## Stretch (only after all Core gates are met)

Full cgroup v2 accounting, parser fuzzing, pivot_root/mount-tree filesystem construction, further kernel mechanisms, extended hardening (signal storms, process-tree stress).

## Scope rule

If a mechanism is needed to make a Core claim truthful, either add its minimum version to Core or weaken the claim. Prefer weakening the claim.
