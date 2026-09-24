# Build State (resume pointer)

- **Branch**: `v2/kernel-sandbox` (never merge to `main`).
- **Current phase/unit**: Phase 6 (network policy modes) — next.
- **Latest verified commit**: see `git log -1` (Phase 5 seccomp commit).
- **Complete**: Phase 0-5. Runner with no_new_privs + Landlock FS + seccomp, fail-closed
  contract, --workspace/--allow-read/--allow-write/--no-default-reads, /tmp default write.
  Tests: `make -C sandbox check` = 57 (18 runner, 12 contract, 14 landlock, 8 seccomp,
  5 pty); `check-asan` = 57. V1 red-team: bypass=11.
- **Partial**: none.
- **Next action (Phase 6)**: network modes. Landlock net (ABI>=4, present=ABI8) restricts
  TCP bind/connect by PORT only — no IP/destination filtering; UDP not covered until ABI10
  (absent). No namespaces on host. Plan: named modes --net=none (default? decide),
  --net=all (intentional egress for `-- claude`), and TCP-port modes via Landlock. For
  no-network: seccomp on socket() by family (deny AF_INET/AF_INET6, allow AF_UNIX/AF_LOCAL
  for local IPC) — add an argument-filtered socket rule in seccomp.c OR a Landlock-net
  layer. Recommendation: implement --net=none via seccomp socket()-family deny (covers TCP
  AND UDP AND raw), and --net=all = no network restriction; document that destination
  filtering is NOT provided. Expose active guarantee in --status. Add AG_LAYER_* or fold
  into a network option that adjusts seccomp/landlock. Tests per mode: TCP connect to a
  local listener denied/allowed; UDP denied/allowed; AF_UNIX always works.
- **Running checks**: `./tests/run_tests.sh` (40); `python3 redteam/run_v1.py` (bypass=11);
  `make -C sandbox check` (57); `bash scripts/capability_audit.sh`.
- **Known constraints/blockers**: live V1 hooks 50 Bash/session (watch for rate-limit block;
  resume next session if hit); PostToolUse gcc check noise on .c writes (cosmetic); firewall
  blocks 'rm -rf' cleanup (use scratchpad / avoid pattern). Do not modify hooks.
