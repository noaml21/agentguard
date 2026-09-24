# Build State (resume pointer)

- **Branch**: `v2/kernel-sandbox` (never merge to `main`).
- **Current phase/unit**: Phase 4 (Landlock filesystem enforcement) — next.
- **Latest verified commit**: see `git log -1` (Phase 3 contract commit).
- **Complete**: Phase 0 (audit); Phase 1 (V1 red-team 11/7/2); Phase 2 (runner:
  options/fdsan/lifecycle/TTY, 18+5 tests); Phase 3 (fail-closed contract: negotiation
  AVAILABLE/REQUESTED/APPLIED, strict vs degraded, --status/--json/--verbose,
  no_new_privs as first real layer; 12 contract tests). All green under `make check` (35)
  and `make check-asan` (35).
- **Partial**: none.
- **Next action (Phase 4)**: register `AG_LAYER_LANDLOCK_FS` in `sandbox.c` (probe via
  landlock ABI runtime detection; apply in child = create ruleset for supported access
  rights, add rules from policy, restrict_self). Needs a workspace/allow-read policy
  source: add `--workspace DIR`, `--allow-read PATH` (repeatable), `--allow-write PATH`
  options now; full policy file is Phase 8. Open rule path fds BEFORE restrict, honor
  setup order (no_new_privs already applied first — but note Landlock restrict_self needs
  nnp; order in ag_apply_layers currently by enum index, so keep NO_NEW_PRIVS index 0 <
  LANDLOCK). Add Landlock FS tests (direct/traversal/symlink/rename/replacement/
  interpreters/descendants), tagged as kernel-feature (skip w/ reason if ABI<1).
- **Running checks**: `./tests/run_tests.sh` (40); `python3 redteam/run_v1.py`
  (bypass=11); `make -C sandbox check` (35); `bash scripts/capability_audit.sh`.
- **Known constraints/blockers**: live V1 hooks: 50 Bash/session; PostToolUse gcc check
  flags multi-file .c writes (cosmetic). Do not modify hooks. Kernel: Landlock ABI 8,
  no namespaces (AppArmor), cgroup v2 delegated.
