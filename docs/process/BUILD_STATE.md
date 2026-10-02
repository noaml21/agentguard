# Build State (resume pointer)

- **Branch**: `v2/kernel-sandbox`. Never merge to `main`, tag, or release without user approval.
- **Status**: **Phases 0–12 COMPLETE. V2 release candidate `2.0.0-rc.1` verified.**
- **Implementation commit**: `5a93443` (last code/test/CI change). Later commits on the
  branch only update this file and BUILD_LOG/README evidence; their own CI run is the
  branch head's run in GitHub Actions.
- **Local evidence (dev host: Ubuntu 24.04.5, kernel 7.0.0-38, Landlock ABI 8, GCC 13)**:
  `make -C sandbox all` warning-clean; `make -C sandbox check` 226/226 (210 shell + 16
  python, 0 skipped); `check-asan` 226/226, no ASan/UBSan/LSan reports (UBSan fatal);
  `tests/run_tests.sh` 40/40; `redteam/run_v1.py` bypass=11 prevented=7 allowed-safe=2
  (unchanged); `redteam/run_v2.py` 36 cases, 0 unexpected; markdown links valid;
  `git diff --check` clean.
- **CI**: run 37016770396 on `5a93443` — success, all 4 jobs (V1; V2 check; V2
  check-asan; V2 redteam). Runner `ubuntu-24.04`, kernel 6.17.0-1022-azure, Landlock ABI 7;
  check and check-asan 220 passed + 6 delegated-cgroup cases skipped with reason;
  redteam matrix identical to committed. Earlier run 37015860344 (`8f50e42`) failed one
  TTY test (test-target race, fixed; BUILD_LOG Phase 12).
- **Supported environment**: Linux x86_64; strict mode needs Landlock ABI >= 6 and
  seccomp; cgroup kill tier only with a writable delegated cgroup v2.
- **Explicit limitations**: no complete same-UID host-service isolation (pathname
  AF_UNIX; historical session-bus escape, not re-executed); workspace contents
  (incl. V1 hook config) unprotected by design; shared `/tmp`, `/dev/shm` reads,
  `/dev/pts`, user netlink; no aggregate resource limits; no destination filtering;
  x86_64 only verified. Full list: `docs/v2/THREAT_MODEL.md`, `docs/v2/V2_BUILD_REPORT.md`.
- **Docs layout**: `docs/v2/` current reference (incl. WALKTHROUGH), `docs/v1/` V1 threat
  model, `docs/process/` history; map in `docs/README.md`.
- **Running operations**: none. Worktree clean after the final commit.
- **Next action**: optional PR from `v2/kernel-sandbox` to `main`, merge, and a `v2.0.0`
  tag/release — only with explicit user approval.
- **Running checks**: `./tests/run_tests.sh`; `python3 redteam/run_v1.py`;
  `make -C sandbox check`; `make -C sandbox check-asan`; `python3 redteam/run_v2.py`;
  `bash scripts/capability_audit.sh`.
- **Session rules**: never re-run the real session-bus / user-manager experiment or touch
  real host services; tests use disposable fixtures only.
- **Known constraints**: live V1 hooks limit 50 Bash calls per Claude session; keep the
  session cwd at the repo root (file policy follows cwd); PostToolUse gcc check noise on
  .c edits is cosmetic. Do not modify hooks.
