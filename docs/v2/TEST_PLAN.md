# AgentGuard V2 Test Plan

All tests run unprivileged, use disposable fixtures under a per-run temporary root,
and never touch the real home directory, credentials, system files, or other repos.
Oracles check the real effect (file changed? connection made? process alive?), not
just exit codes.

## Suites

| Suite | Location | Needs | Runs in CI |
|---|---|---|---|
| V1 regression | `tests/run_tests.sh` | bash, jq, python3, gcc | yes |
| V1 red-team corpus | `redteam/run_v1.py` | same | yes |
| Runner unit/integration | `sandbox/tests/` via `make -C sandbox check` | gcc, python3 | yes |
| Kernel-feature tests | same, tagged | Landlock ABI ≥ N, seccomp | yes, skip with reason when the runner kernel lacks the feature |
| Host-only enhanced | same, tagged | namespaces / delegated cgroup | skip with reason in CI; never reported as verified when skipped |
| Sanitizers | `make -C sandbox check-asan` | gcc ASan/UBSan | yes |
| V2 red-team replay | `redteam/run_v2.py` | built runner | yes (feature-gated cases skip with reason) |

## Required cases by phase

- **Phase 2**: exit-status propagation (0, N, signal → 128+N); argv preserved exactly
  (spaces, globs, empty args); no shell involved; EUID 0 refused; inherited file, pipe,
  TCP socket, unix socket fds are closed in the target; stdio preserved; SIGTERM to
  runner terminates tree; timeout kills tree only; orphaned grandchildren reaped;
  unrelated process survives; repeated runs leak no processes; child crash reported.
- **Phase 2 TTY** (pty-driven via python `pty`): target sees a TTY, is foreground,
  Ctrl-C reaches it, SIGWINCH/resize reaches it, runner restores foreground.
- **Phase 3**: available+applied; required-but-unavailable refuses (target marker
  file never created); available-but-setup-fails refuses; explicit degraded run lists
  missing layers; no silent downgrade.
- **Phase 4**: workspace write ok; outside write denied (direct, `..`, absolute,
  symlink, rename, path replacement after start, via python/perl/sh -c, via
  grandchild); required reads permitted.
- **Phase 5**: each denied syscall returns the documented errno; allowed ordinary work
  (compilers, git, python) succeeds; restrictions inherited by descendants.
- **Phase 6**: per network mode: TCP connect to a local listener allowed/denied as
  specified; UDP send allowed/denied as specified; AF_UNIX local IPC works.
- **Phase 8**: malformed policies rejected with useful errors; policy file inside the
  writable workspace refused; sandboxed process cannot modify the policy/binary.
- **Phase 9**: signal to an outside same-UID process denied (scope); ptrace denied;
  abstract unix connect to outside listener denied; pathname unix socket outside
  workspace (documented per ABI).
