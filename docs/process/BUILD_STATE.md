# Build State (resume pointer)

- **Branch**: `v2/kernel-sandbox` (never merge to `main`).
- **Current phase/unit**: Phase 9 (host IPC / same-UID surface) — IN PROGRESS, slices 1–3
  verified. Real closure gate NOT satisfied. Do NOT start Phase 10.
- **Latest verified commit**: see `git log -1` (Phase 9 slice 3: self-only scheduling
  setters and POSIX message-queue evidence; slice 2 = `b305ee5`).
- **Complete**: Phase 0-8. Runner with no_new_privs + opportunistic cgroup_kill + Landlock FS
  + Landlock scope (signal + abstract unix, ABI >= 6, required) + seccomp (deny-list,
  clone-flag filter, clone3 ENOSYS, io_uring denied, prlimit64 pid 0 only), `--net none|all`,
  rlimits, `--timeout` + cgroup.kill teardown, `--policy`, fail-closed contract, status/JSON.
  Tests: `make -C sandbox check` = 210 (18 runner, 12 contract, 14 landlock, 17 seccomp,
  21 network, 14 resource [6 host-only cgroup cases ran here], 66 policy, 27 host-IPC,
  16 extended host-IPC, 5 pty), 0 skipped on the dev host; `check-asan` = 210, no sanitizer
  reports. V1: `tests/run_tests.sh` 40/40 (re-run 2026-09-27). CI runs ONLY the V1 suite;
  green CI is not evidence for V2 tests (Phase 12).
- **Phase 9 done (slice 1, 2026-09-26)**: `landlock_scope` layer — outside signals
  (kill, SIGTERM, pidfd_send_signal, grandchild, supervisor) and outside abstract-unix
  connects denied, VERIFIED with disposable fixtures; inside abstract sockets/signals work.
  seccomp `prlimit64` pid!=0 → EPERM, VERIFIED (sentinel limits unchanged; before the rule
  they changed to 77/66/55). Compat verified: socketpair, python asyncio/threads/subprocess,
  gcc, git, node child_process, util-linux `prlimit CMD`.
- **OPEN (VERIFIED escape, all modes)**: pathname AF_UNIX to same-UID host services — the
  session D-Bus / `systemd-run --user` path (THREAT_MODEL §4.1). Nothing applied for it yet.
  No strict host-isolation claim may be made. Not contacted or retested in slice 2.
- **Phase 9 done (slice 2, 2026-09-27)**: SysV shm/sem/msg access blocked by seccomp,
  demonstrated with owned objects and external state oracles; independent seccomp/Landlock
  memory protection measured with a traceable outside sentinel; Unix/pidfd inheritance
  rechecked; all 64 `--keep-fd` slots fixed. Candidate Unix socket/socketpair-DGRAM denial
  measured: blocks fixture traffic but breaks multiprocessing.Manager. Preserve normal
  IPC; strict/degraded status explicitly reports `host_ipc.isolation_enforced:false`.
  Candidate remains test-only. gcc/git/Node, claude version, asyncio/pipe multiprocessing,
  NSS localhost/syslog fallback checked with isolated home and no real service contact.
  Surface inventory in THREAT_MODEL §6; architecture/test plan/walkthrough updated.
- **Phase 9 done (slice 3, 2026-09-27)**: reproduced outside scheduling mutations;
  seccomp now limits sched_setparam/setscheduler/setaffinity/setattr to pid 0 and
  setpriority/ioprio_set to single-process selector + who 0. Baseline/degraded effects
  reproduced on private sentinel processes/groups; strict values unchanged. Self APIs
  and nice/taskset/chrt/ionice commands work. Explicit PID/TID setters remain denied,
  including other threads inside the sandbox. Owned POSIX queue send/receive denied by
  current Landlock configuration, independently of seccomp; outside contents preserved.
- **Further measured limits**: NETLINK_USERSOCK reaches an outside fixture; default
  `/dev/shm` reads and `/dev/pts` writes remain shared authority. Fixture TIOCSTI fails
  equally outside and inside (host policy, not AgentGuard). No exhaustive host isolation.
- **Phase 9 remaining / exact resume action**: review the remaining host-IPC design against
  THREAT_MODEL §6 and the unchanged Phase 9 gate. The real session-bus authority regression
  is still absent and requires separately explicit authorization; do not attempt it, mark
  its finding closed, or start Phase 10. The candidate/filter evaluation and reporting
  fallback do not prove that authority path blocked. All remaining scoped fixture work
  from the checkpoint (memory, inherited fds, SysV, Unix candidate/compatibility) is recorded;
  extra scheduling/POSIX queue inventory is also covered. Remaining host-IPC exposure
  (pathname services, netlink, shared default grants, delegated fds) stays explicit.
- **Running checks**: `./tests/run_tests.sh` (40); `python3 redteam/run_v1.py` (bypass=11);
  `make -C sandbox check` (210); `make -C sandbox check-asan` (210);
  `bash scripts/capability_audit.sh`. Sanitizers build separately in `sandbox/build/asan`.
- **Known constraints/blockers**: live V1 hooks 50 Bash/session (watch for rate-limit block;
  resume next session if hit); PostToolUse gcc check noise on .c writes (cosmetic); firewall
  blocks 'rm -rf' cleanup (use scratchpad / avoid pattern); file-policy hook blocks docs/
  writes when the session cwd is sandbox/ — keep cwd at the repo root. Do not modify hooks.
