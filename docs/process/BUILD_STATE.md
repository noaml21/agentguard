# Build State (resume pointer)

- **Branch**: `v2/kernel-sandbox` (never merge to `main`).
- **Current phase/unit**: Phase 5 (seccomp-BPF + no_new_privs) — next.
- **Latest verified commit**: see `git log -1` (Phase 4 Landlock commit).
- **Complete**: Phase 0 (audit); Phase 1 (V1 red-team 11/7/2); Phase 2 (runner); Phase 3
  (fail-closed contract); Phase 4 (Landlock FS: landlock.c/policy.c, --workspace/--allow-*,
  14 kernel-feature tests). All green: `make -C sandbox check` = 49 tests; `check-asan` = 49.
- **Partial**: none.
- **Next action (Phase 5)**: record the seccomp design comparison (libseccomp vs
  hand-written cBPF -> hand-written cBPF chosen; libseccomp headers absent, filter small)
  in docs/v2/ARCHITECTURE.md, then add `seccomp.{h,c}`: arch check (audit AUDIT_ARCH_X86_64),
  deny list derived from threat model (ptrace, mount/pivot_root/unshare/setns dangerous
  namespace ops, kernel/module/reboot: init_module/finit_module/delete_module/kexec_load/
  reboot, and argument-filtered socket() by family where it doesn't break local IPC).
  Register AG_LAYER_SECCOMP (index 2, applied LAST so the filter needn't allow setup
  syscalls). Per-rule doc: threat + why agent work doesn't need it + compat impact. Tests:
  each denied syscall returns documented errno; ordinary work (gcc/git/python) still runs;
  descendants inherit. Tag kernel-feature.
- **Running checks**: `./tests/run_tests.sh` (40); `python3 redteam/run_v1.py` (bypass=11);
  `make -C sandbox check` (49); `bash scripts/capability_audit.sh`.
- **Known constraints/blockers**: live V1 hooks: 50 Bash/session (may need to resume in a
  new session); PostToolUse gcc check flags multi-file .c writes (cosmetic); firewall may
  block cleanup commands containing rm -rf (use scratchpad). Do not modify hooks. Kernel:
  Landlock ABI 8, no namespaces, cgroup v2 delegated. Makefile now tracks header deps.
