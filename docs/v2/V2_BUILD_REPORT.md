# AgentGuard V2 build report

Release status: **verified release candidate `2.0.0-rc.1`** on branch `v2/kernel-sandbox`.
Not merged to `main`, not tagged, no GitHub release; those steps await maintainer
approval. Exact commits, local counts and CI runs for the final head are in
[`docs/process/BUILD_STATE.md`](../process/BUILD_STATE.md); per-session evidence is in
[`BUILD_LOG.md`](../process/BUILD_LOG.md).

## Architecture

`agentguard-run` is a ~2.8k-line C launcher (sources + headers) (no dependencies beyond kernel UAPI headers).
An unrestricted supervisor validates policy, probes the kernel, forks, and owns the
lifecycle (signal forwarding, deadline, cgroup kill, reaping). The child restricts itself
in a fixed order — owned cgroup, fd sanitation, rlimits, no_new_privs, Landlock filesystem
rules, Landlock scope, seccomp-BPF — and only then execs the target. Each layer is
negotiated as available / requested / applied; strict mode refuses unless every required
layer applies, and the target never runs before enforcement. Details:
[ARCHITECTURE.md](ARCHITECTURE.md).

## Verified security properties (strict mode; THREAT_MODEL §4)

- Filesystem: reads and writes outside the workspace and explicit grants are denied for
  the target and every descendant, independent of spelling (symlinks, `..`, hard links,
  renames, interpreters, grandchildren); `$HOME` is not readable by default.
- `--net none`: no IP socket of any family can be created; `--net all` is host networking.
- Same-UID process interference: signals and abstract-Unix connects to outside processes,
  ptrace/process_vm, sensitive `/proc/PID` access, outside `prlimit` and scheduling
  changes, SysV IPC — each demonstrated against disposable sentinels with a baseline that
  shows the effect without AgentGuard.
- Privilege and kernel surface: no_new_privs; namespaces, mounts, bpf, perf, io_uring,
  kernel modules denied.
- Control plane: a policy file or installed runner inside any writable root is refused;
  17 tamper spellings leave policy and runner byte-identical.
- Fail-closed contract: unavailable or failing required layers never run the target;
  degraded mode lists missing guarantees; status always reports host-IPC isolation as false.

## Comparison with V1 (Phase 11, `redteam/results/comparison.md`)

36 effect-based cases with a baseline control each. V1 (text guardrails): 8 prevented,
24 bypasses, 1 false positive, 3 allowed-safe. V2 (kernel boundary): 17 prevented — every
V1 bypass whose target is outside the workspace (14) plus the cases V1 also stopped —,
14 allowed because they act inside the granted workspace (by design), 4 legitimate
workflows allowed, 1 out of scope (text-only case), **0 unexpected**. V1 remains useful as
early feedback, audit and snapshots; it is not a boundary.

## Compatibility (Phase 10)

Under the default policy: shells, git (init/add/commit/status/diff/branch/merge, hooks),
make + gcc multi-file builds, Python (subprocess, asyncio, threads), Node `child_process`,
interactive TTY (foreground, Ctrl-C, resize), deadlines. `agentguard-agent -- claude`
starts Claude Code with its state writable; the V1 hook suite passes unchanged inside the
runner. Known incompatibilities, by design: SysV IPC; explicit-TID scheduling calls;
programs that require `clone3` without fallback (none observed); anything needing
`$HOME` files outside granted paths.

## Tests

| Suite | Dev host (Ubuntu 24.04.5, kernel 7.0.0-38, ABI 8) |
|---|---|
| V1 `tests/run_tests.sh` | 40/40 |
| V1 red-team `redteam/run_v1.py` | 20 cases; bypass 11, prevented 7, allowed-safe 2 (unchanged baseline) |
| `make -C sandbox check` | 226/226 (11 suites; 0 skipped) |
| `make -C sandbox check-asan` | 226/226, no ASan/UBSan/LSan reports (UBSan fatal) |
| `redteam/run_v2.py` | 36 cases, 0 unexpected |

## CI

GitHub Actions on pinned `ubuntu-24.04` (measured kernel 6.17 azure, Landlock ABI 7):
V1 regression + corpus; V2 `check`, `check-asan`, `redteam` as separate jobs behind a
kernel-feature preflight that skips a tier visibly (warning + step summary) instead of
passing it when a required layer is missing. The 6 delegated-cgroup cases skip with a
reason on GitHub runners and are verified only on the dev host.

## Limitations (not buried)

- **No complete same-UID host-service isolation.** Pathname AF_UNIX is not mediated on the
  verified ABIs; a sandboxed process reached the session D-Bus and asked `systemd --user`
  to start an unrestricted process (Phase 6, historical; not re-executed at the final
  head; no later mechanism mediates it). `host_ipc.isolation_enforced` is false in every
  mode. Use a separate user, VM or container when that isolation is required.
- Everything inside the writable workspace — including a workspace `.env` and V1's own
  hook configuration — is modifiable by the agent.
- `/tmp` is writable and `/dev/shm`, `/dev/pts`, user netlink are shared by default.
- No aggregate memory/process limits; rlimits are per process; cgroup kill is
  opportunistic.
- No destination filtering; `--net all` is full host networking.
- Not a VM or container; kernel bugs are out of scope; root is refused.
- Verified on x86_64 only.

## Phase status

Phases 0–12 complete per [PLAN.md](PLAN.md) gates, with Phase 9 closed by explicitly
weakening the host-IPC claim (scope rule) rather than adding a mechanism.
