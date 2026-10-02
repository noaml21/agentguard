# Build State (resume pointer)

- **Branch**: `v2/kernel-sandbox` (never merge to `main` without user approval).
- **Current phase/unit**: Phase 12 (CI tiers + README/release docs) — next.
- **Phase 11 COMPLETE (2026-10-02)**: `redteam/run_v2.py` + `cases/expanded.json`;
  36 cases → prevented 17, granted-authority 14, legitimate 4, out-of-scope 1,
  unexpected 0. Artifacts `redteam/results/{v2_results.json,comparison.md}`.
- **Phase 10 COMPLETE (2026-10-02)**: `sandbox/scripts/agentguard-agent` wrapper,
  `make -C sandbox install`, `tests/devworkflow_test.sh` (16). `make check` 226/226,
  `check-asan` 226/226 clean, V1 40/40 (also 40/40 inside the runner).
- **Complete**: Phases 0–11. Phase 9 closed 2026-10-02 by classification under the PLAN gate
  and scope rule (BUILD_LOG "Session 4"): pathname AF_UNIX same-UID host services are
  **not isolated** (degraded, all modes, reported `host_ipc.isolation_enforced:false`);
  the Phase 6 session-bus escape is historical VERIFIED evidence, not re-executed at the
  final head, and still applicable. No complete same-UID host isolation claim.
- **Runner**: no_new_privs + opportunistic cgroup_kill + Landlock FS + Landlock scope
  (signal + abstract unix, ABI >= 6, required) + seccomp (deny-list, clone-flag filter,
  clone3 ENOSYS, io_uring, SysV, self-only prlimit64/scheduling setters), `--net none|all`,
  rlimits, `--timeout` + cgroup.kill teardown, `--policy`, fail-closed contract, status/JSON.
- **Verified at Phase 9 closure (code = `3be56ca`, dev host kernel 7.0.0-38)**:
  `make -C sandbox check` 210/210 (0 skipped); `tests/run_tests.sh` 40/40;
  `git diff --check` clean. check-asan last run at `3be56ca`: 210/210, no reports.
- **CI** runs only the V1 suite until Phase 12; green CI is not V2 evidence.
- **Running checks**: `./tests/run_tests.sh`; `python3 redteam/run_v1.py`;
  `make -C sandbox check`; `make -C sandbox check-asan`; `bash scripts/capability_audit.sh`.
- **Session scope rule (2026-10-02)**: never re-run the real session-bus / user-manager
  experiment or touch real host services; all tests use disposable fixtures.
- **Known constraints**: live V1 hooks limit 50 Bash calls per Claude session (batch work;
  resume in a new session when hit); PostToolUse gcc check noise on .c writes (cosmetic);
  firewall blocks some cleanup spellings; keep session cwd at repo root. Do not modify hooks.
