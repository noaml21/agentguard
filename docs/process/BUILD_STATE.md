# Build State (resume pointer)

- **Branch**: `v2/kernel-sandbox` (never merge to `main`).
- **Current phase/unit**: Phase 9 (host IPC / same-UID surface) — next, not started.
  SECURITY-CRITICAL: do it before Phase 10.
- **Latest verified commit**: see `git log -1` (Phase 8 policy commit).
- **Complete**: Phase 0-8. Runner with no_new_privs + opportunistic cgroup_kill + Landlock FS
  + seccomp (deny-list, clone-flag filter, clone3 ENOSYS, io_uring denied), `--net none|all`,
  rlimits (core=0; `--max-file-size`, `--max-open-files`), `--timeout` + cgroup.kill
  teardown, `--policy` (strict parser, inode location check, runner-binary check),
  fail-closed contract, status/JSON incl. network + resources + control.
  Tests: `make -C sandbox check` = 167 (18 runner, 12 contract, 14 landlock, 17 seccomp,
  21 network, 14 resource [6 host-only cgroup cases ran here], 66 policy, 5 pty);
  `check-asan` = 167. V1: `tests/run_tests.sh` 40/40; red-team bypass=11 (baseline).
  CI: Phase 6 run 36180346531 and Phase 7 run 36181400237 green.
- **Partial**: none.
- **Open finding for Phase 9 (VERIFIED escape)**: same-UID AF_UNIX services are reachable;
  `systemd-run --user` via the session D-Bus spawns an unconfined process from inside the
  sandbox (THREAT_MODEL §4.1). Landlock ABI 8 cannot mediate pathname-unix connects.
- **Phase 9 baseline (measured 2026-09-26, no code changed)**: Landlock scoping
  (abstract-unix + signal) works on ABI 8 in a standalone probe (EPERM for outside kill and
  abstract connect; socketpair ok). Current runner: outside `kill -0`, `pidfd_send_signal`,
  `prlimit --pid` (effect verified), abstract connect (effect verified), and session-bus
  connect all SUCCEED. Probe source is reproduced in BUILD_LOG (Phase 9 baseline).
  Suggested first slice: add a `landlock_scope` layer (probe ABI>=6; `scoped` field in the
  ruleset attr — Ubuntu's UAPI headers may lack it, define the struct locally like the
  probe did), plus a seccomp rule allowing `prlimit64` only with pid arg 0 (check glibc
  `setrlimit`/`getrlimit` → prlimit64(0,…) first), then the host-IPC test suite.
- **Next action (Phase 9)**, in a FRESH Claude session (Bash limit): (1) re-reproduce the
  systemd-run escape with an effect oracle (outside process ran? its Seccomp/NoNewPrivs);
  (2) check what Landlock ABI 8 scoping gives (LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET,
  LANDLOCK_SCOPE_SIGNAL — not applied yet) and whether any Core mechanism can stop
  pathname-unix connects (seccomp cannot read sockaddr; env scrubbing is not a boundary).
  seccomp cannot tell an AF_UNIX `connect()` from a TCP one, so evaluate (a) denying
  `socket(AF_UNIX)` (socketpair stays allowed) in a stricter mode, with compat tests, and
  (b) otherwise weakening/blocking the strict claim. (3) prlimit64 against an outside sentinel
  (candidate: seccomp allow only pid arg 0); (4) signals/ptrace/process_vm/pidfd/abstract
  unix/inherited-fd fixtures; (5) classify every surface in THREAT_MODEL.
- **Running checks**: `./tests/run_tests.sh` (40); `python3 redteam/run_v1.py` (bypass=11);
  `make -C sandbox check` (167); `bash scripts/capability_audit.sh`.
- **Known constraints/blockers**: live V1 hooks 50 Bash/session (watch for rate-limit block;
  resume next session if hit); PostToolUse gcc check noise on .c writes (cosmetic); firewall
  blocks 'rm -rf' cleanup (use scratchpad / avoid pattern); file-policy hook blocks docs/
  writes when the session cwd is sandbox/ — keep cwd at the repo root. Do not modify hooks.
