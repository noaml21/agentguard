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
- **Phase 6** (`sandbox/tests/network_test.sh`, 21 cases; seccomp hardening in
  `seccomp_test.sh`): loopback TCP+UDP listeners on 127.0.0.1 and ::1 run *outside* the
  sandbox and log every accepted connection/datagram. `none`: IPv4/IPv6 TCP connect and UDP
  send fail with EACCES; raw IP, AF_PACKET, AF_VSOCK denied; bash `/dev/tcp` and a descendant
  denied; default is `none`; the listeners' log stays **empty** (effect oracle); AF_UNIX
  socketpair + pathname socket round trip works. `all`: IPv4 TCP/UDP and IPv6 TCP arrive at
  the listeners; descendant connects; AF_UNIX works. Contract: status JSON reports mode and
  `enforced`; strict + seccomp unavailable refuses (125); degraded reports `enforced:false`
  and warns; invalid `--net` value rejected. IPv6 cases skip with a reason if `::1` is absent.
  Seccomp hardening: clone(CLONE_NEWUSER|CLONE_NEWNET) EPERM, clone3 ENOSYS, fsopen,
  pidfd_getfd, io_uring_setup EPERM; fork+pthread, python threads+subprocess, git
  init/add/commit still work. Discrimination baseline (same helper, unsandboxed, dev host):
  clone(NEWUSER) and clone3 **succeed**, pidfd_getfd → EBADF, io_uring_setup → EFAULT; fsopen
  and clone(NEWNET) are EPERM even unsandboxed (not independently proven there).
- **Phase 7** (`sandbox/tests/resource_test.sh`, 14 cases on the dev host): core soft+hard
  0 in a descendant and cannot be raised; `--max-file-size` makes a python write fail
  EFBIG and a shell writer stop, file capped exactly at the bound; large writes work
  without the flag; `--max-open-files` gives EMFILE below the bound and a gcc workflow still
  works at 64; bad values rejected; status JSON reports resources. **Host-only**
  (skip with reason when `cgroup_kill` is unavailable, never counted as verified): target
  and descendant are in `agentguard-run.<pid>`; target cannot write itself back to the
  parent cgroup; a setsid escapee **survives** with the layer disabled
  (`AGENTGUARD_TEST_UNAVAIL=cgroup_kill`) and **dies** with it enabled (discrimination);
  timeout exits 124 and kills the escapee; an unrelated process survives; the parent
  cgroup's child list and `subtree_control` are identical before/after. The escapee
  fixture waits until the escapee is in its own session: without that wait the ordinary
  group teardown kills it and the case proves nothing (bug found while writing the test).
- **Phase 8**: malformed policies rejected with useful errors; policy file inside the
  writable workspace refused; sandboxed process cannot modify the policy/binary.
- **Phase 9**: signal to an outside same-UID process denied (scope); ptrace denied;
  abstract unix connect to outside listener denied; pathname unix socket outside
  workspace (documented per ABI).
