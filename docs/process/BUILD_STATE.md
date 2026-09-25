# Build State (resume pointer)

- **Branch**: `v2/kernel-sandbox` (never merge to `main`).
- **Current phase/unit**: Phase 8 (policy format + integrity) — next, not started.
- **Latest verified commit**: see `git log -1` (Phase 7 resource-limits commit).
- **Complete**: Phase 0-7. Runner with no_new_privs + opportunistic cgroup_kill + Landlock FS
  + seccomp (deny-list, clone-flag filter, clone3 ENOSYS, io_uring denied), `--net none|all`,
  rlimits (core=0; `--max-file-size`, `--max-open-files`), `--timeout` + cgroup.kill
  teardown, fail-closed contract, status/JSON incl. network + resources.
  Tests: `make -C sandbox check` = 101 (18 runner, 12 contract, 14 landlock, 17 seccomp,
  21 network, 14 resource [6 host-only cgroup cases ran here], 5 pty); `check-asan` = 101.
  V1: `tests/run_tests.sh` 40/40; red-team bypass=11 (baseline).
- **Partial**: none.
- **Open finding for Phase 9 (VERIFIED escape)**: same-UID AF_UNIX services are reachable;
  `systemd-run --user` via the session D-Bus spawns an unconfined process from inside the
  sandbox (THREAT_MODEL §4.1). Landlock ABI 8 cannot mediate pathname-unix connects.
- **Next action (Phase 8)**: read PLAN row 8; narrow policy file format + strict parser
  (reject unknown/duplicate keys, malformed values, unsafe paths, unsupported version);
  policy opened + validated in the parent before fork; refuse a policy inside any writable
  root; tests that the sandboxed target cannot modify the policy or runner binary for the
  next run (Landlock already denies writes outside workspace//tmp — verify, incl. symlink
  and rename replacement). Consider asking the user whether to pull Phase 9 (host-IPC
  escape above) ahead of Phase 8, since it currently voids every guarantee.
- **Running checks**: `./tests/run_tests.sh` (40); `python3 redteam/run_v1.py` (bypass=11);
  `make -C sandbox check` (101); `bash scripts/capability_audit.sh`.
- **Known constraints/blockers**: live V1 hooks 50 Bash/session (watch for rate-limit block;
  resume next session if hit); PostToolUse gcc check noise on .c writes (cosmetic); firewall
  blocks 'rm -rf' cleanup (use scratchpad / avoid pattern); file-policy hook blocks docs/
  writes when the session cwd is sandbox/ — keep cwd at the repo root. Do not modify hooks.
