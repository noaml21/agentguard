# Build State (resume pointer)

- **Branch**: `v2/kernel-sandbox` (never merge to `main`).
- **Current phase/unit**: Phase 7 (resource limits) — next.
- **Latest verified commit**: see `git log -1` (Phase 6 network commit).
- **Complete**: Phase 0-6. Runner with no_new_privs + Landlock FS + seccomp (deny-list,
  clone-flag filter, clone3 ENOSYS, io_uring denied), `--net none|all` (socket-family
  allowlist), fail-closed contract, status/JSON incl. network enforcement.
  Tests: `make -C sandbox check` = 87 (18 runner, 12 contract, 14 landlock, 17 seccomp,
  21 network, 5 pty); `check-asan` = 87. V1 red-team: bypass=11.
- **Partial**: none.
- **Open finding for Phase 9 (VERIFIED escape)**: same-UID AF_UNIX services are reachable;
  `systemd-run --user` via the session D-Bus spawns an unconfined process from inside the
  sandbox (THREAT_MODEL §4.1). Landlock ABI 8 cannot mediate pathname-unix connects.
- **Next action (Phase 7)**: 7.1 rlimits with honest per-process semantics; 7.2 reuse the
  existing lifecycle `--timeout` deadline (no second timer); 7.3 delegated cgroup v2 probe →
  owned child cgroup + cgroup.kill when writable, else reported fallback.
- **Running checks**: `./tests/run_tests.sh` (40); `python3 redteam/run_v1.py` (bypass=11);
  `make -C sandbox check` (57); `bash scripts/capability_audit.sh`.
- **Known constraints/blockers**: live V1 hooks 50 Bash/session (watch for rate-limit block;
  resume next session if hit); PostToolUse gcc check noise on .c writes (cosmetic); firewall
  blocks 'rm -rf' cleanup (use scratchpad / avoid pattern); file-policy hook blocks docs/
  writes when the session cwd is sandbox/ — keep cwd at the repo root. Do not modify hooks.
