# Build State (resume pointer)

- **Branch**: `v2/kernel-sandbox` (never merge to `main`).
- **Current phase/unit**: Phase 9 (host IPC / same-UID surface) — IN PROGRESS, first slice
  done. SECURITY-CRITICAL: finish before Phase 10. Do NOT start Phase 10.
- **Latest verified commit**: see `git log -1` (Phase 9 slice 1: landlock_scope + prlimit64).
- **Complete**: Phase 0-8. Runner with no_new_privs + opportunistic cgroup_kill + Landlock FS
  + Landlock scope (signal + abstract unix, ABI >= 6, required) + seccomp (deny-list,
  clone-flag filter, clone3 ENOSYS, io_uring denied, prlimit64 pid 0 only), `--net none|all`,
  rlimits, `--timeout` + cgroup.kill teardown, `--policy`, fail-closed contract, status/JSON.
  Tests: `make -C sandbox check` = 194 (18 runner, 12 contract, 14 landlock, 17 seccomp,
  21 network, 14 resource [6 host-only cgroup cases ran here], 66 policy, 27 host-IPC,
  5 pty), 0 skipped on the dev host; `check-asan` = 194, no sanitizer reports.
  V1: `tests/run_tests.sh` 40/40 (re-run in Phase 9 slice 1). CI runs ONLY the V1 suite; green CI is not evidence for V2 tests (Phase 12).
- **Phase 9 done (slice 1, 2026-09-26)**: `landlock_scope` layer — outside signals
  (kill, SIGTERM, pidfd_send_signal, grandchild, supervisor) and outside abstract-unix
  connects denied, VERIFIED with disposable fixtures; inside abstract sockets/signals work.
  seccomp `prlimit64` pid!=0 → EPERM, VERIFIED (sentinel limits unchanged; before the rule
  they changed to 77/66/55). Compat verified: socketpair, python asyncio/threads/subprocess,
  gcc, git, node child_process, util-linux `prlimit CMD`.
- **OPEN (VERIFIED escape, all modes)**: pathname AF_UNIX to same-UID host services — the
  session D-Bus / `systemd-run --user` path (THREAT_MODEL §4.1). Nothing applied for it yet.
  No strict host-isolation claim may be made.
- **Phase 9 remaining**: (1) pathname AF_UNIX decision: evaluate a mode that denies
  `socket(AF_UNIX)` (socketpair stays; consider denying `socketpair(SOCK_DGRAM)`, which can
  sendto pathname datagram sockets) with compat tests (node/claude, python multiprocessing,
  nscd/syslog fallbacks), else make strict mode report/refuse the guarantee explicitly;
  a regression that proves the session-bus authority path is blocked (needs the user's
  explicit go-ahead for the escape reproduction — a previous attempt was stopped);
  (2) ptrace/process_vm/`/proc/<pid>` against an outside sentinel (Landlock's ptrace
  restriction should also apply); (3) inherited-fd re-check incl. unix/pidfd; (4) disposable
  SysV IPC fixture (never the real segment); (5) classify every surface in THREAT_MODEL;
  (6) WALKTHROUGH update; (7) full gate + V1 40/40.
- **Running checks**: `./tests/run_tests.sh` (40); `python3 redteam/run_v1.py` (bypass=11);
  `make -C sandbox check` (194); `bash scripts/capability_audit.sh`.
- **Known constraints/blockers**: live V1 hooks 50 Bash/session (watch for rate-limit block;
  resume next session if hit); PostToolUse gcc check noise on .c writes (cosmetic); firewall
  blocks 'rm -rf' cleanup (use scratchpad / avoid pattern); file-policy hook blocks docs/
  writes when the session cwd is sandbox/ — keep cwd at the repo root. Do not modify hooks.
