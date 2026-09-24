# Build State (resume pointer)

- **Branch**: `v2/kernel-sandbox` (never merge to `main`).
- **Current phase/unit**: Phase 3 (fail-closed setup contract) — next.
- **Latest verified commit**: see `git log -1` (Phase 2 runner commit).
- **Complete**: Phase 0 (audit); Phase 1 (V1 red-team: 11 bypass/7 prevented/2 safe);
  Phase 2 (runner: options, fdsan, lifecycle, TTY; 18 integration + 5 pty tests, green
  under ASan/UBSan). Build: `make -C sandbox check` and `check-asan`.
- **Partial**: none.
- **Next action (Phase 3)**: add a layer-negotiation module tracking AVAILABLE vs
  REQUESTED vs APPLIED per enforcement layer; use the existing report pipe so the child
  reports precise setup failure to the parent; add `--strict` (default) vs
  `--degraded` and a `--status` output (human + `--json`). Tests: required-but-unavailable
  refuses (target marker never created); setup-fails refuses; degraded lists missing
  layers; no silent downgrade. This precedes Landlock (Phase 4) so enforcement plugs into
  the contract. The child's sandbox-setup hook point is marked in `lifecycle.c`
  ("Later phases install Landlock/seccomp here").
- **Running checks**: `./tests/run_tests.sh` (40); `python3 redteam/run_v1.py`
  (bypass=11); `make -C sandbox check` (23); `bash scripts/capability_audit.sh`.
- **Known constraints/blockers**: live V1 hooks: 50 Bash req/session; PostToolUse
  gcc syntax check flags multi-file .c writes (cosmetic; files write fine). Do not modify
  hooks. V2 code lives outside control-plane paths.
