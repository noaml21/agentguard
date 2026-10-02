# AgentGuard

[![CI](https://github.com/noaml21/agentguard/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/noaml21/agentguard/actions/workflows/ci.yml)

AgentGuard runs AI coding agents on Linux behind two layers: workflow guardrails that
inspect each tool request, and a kernel-enforced sandbox around the agent's whole process tree.

| | V1 workflow guardrails | V2 kernel sandbox |
|---|---|---|
| Component | Claude Code hooks (`.claude/settings.json`) | `agentguard-run`, a C launcher |
| Decides on | the text of a Bash/Read/Edit/Write request | the effect of each syscall, for the agent and all descendants |
| Provides | command and file policy, snapshots, commit checks, audit log | filesystem, network and same-UID restrictions applied by the kernel |
| Limit | re-spelling a command bypasses it (11 of 20 corpus cases) | see [Limitations](#limitations) |

V1 gives early, readable feedback to a cooperative agent. V2 is the boundary. V2 is
merged on `main`; the runner reports version `2.0.0-rc.1` and no release has been tagged yet.

## What V2 enforces

- Writes only to the workspace, `/tmp` and explicit grants; reads also from system
  locations. The rest of `$HOME` is not readable. Rules bind to inodes, so symlinks, `..`, hard links and renames
  do not escape (Landlock).
- `--net none` (default): no IP socket of any family can be created. `--net all`: host networking.
- No signals to, or abstract-Unix connections into, processes outside the sandbox (Landlock scope).
- seccomp-BPF denies ptrace, namespaces, mounts, bpf, io_uring and SysV IPC; it limits
  `prlimit64` and scheduling setters to the calling process.
- Fail-closed startup: strict mode runs the command only if every required layer
  applied; `--degraded` runs anyway and reports what is missing.
- `--timeout` tears down the whole tree; `cgroup.kill` also catches `setsid` escapees
  when a delegated cgroup is available.
- With `--policy`, the policy file and the runner must sit outside every writable root
  (checked by inode), so a run cannot change the next run's policy.
- Every descendant inherits the restrictions; no_new_privs blocks setuid escalation.

## Architecture

```text
agentguard-run [options] -- COMMAND
 ├─ supervisor (unrestricted): validate policy, probe kernel, fork,
 │                             forward signals, deadline, kill and reap the tree
 └─ child: cgroup join → close fds → rlimits → no_new_privs
           → Landlock FS → Landlock scope → seccomp → exec COMMAND
               └─ e.g. claude ─┬─ V1 hooks
                               └─ bash, git, gcc, python, node … (inherit every layer)
```

If any required step fails, the child exits before `exec`. Details: [architecture](docs/v2/ARCHITECTURE.md).

## Quick start

```bash
make -C sandbox                  # -Wall -Wextra -Werror build
make -C sandbox install          # agentguard-run, agentguard-agent -> ~/.local/bin
agentguard-run --status          # layers this kernel can enforce
agentguard-run -- bash           # writes limited to the current directory and /tmp, no network
agentguard-agent -- claude       # Claude Code: repo writable, ~/.claude state writable, network on
```

Strict mode needs Landlock ABI 6 or later (Linux 6.12+) and seccomp.
[`agentguard-agent`](sandbox/scripts/agentguard-agent) is a short wrapper that spells out
that recipe; set `AGENTGUARD_NET=none` for offline agents.

## Evidence

Tests run unprivileged against disposable fixtures. Oracles check effects (file bytes,
socket arrivals, process liveness), not just exit codes.

| Suite | Result |
|---|---|
| V1 hooks, `tests/run_tests.sh` | 40/40 |
| V2, `make -C sandbox check` (11 suites) | 226/226 on the dev host (kernel 7.0, Landlock ABI 8) |
| V2 under ASan + UBSan, `check-asan` | 226/226, no sanitizer reports |
| V1 vs V2 red team, `redteam/run_v2.py` | 36 cases, 0 unexpected; V2 prevents all 14 V1 bypasses that target files outside the workspace ([matrix](redteam/results/comparison.md)) |
| GitHub Actions, Ubuntu 24.04 (kernel 6.17, ABI 7) | all tiers; 6 delegated-cgroup cases skip there with a stated reason |

## Limitations

- **Same-UID host services are not isolated.** Pathname Unix sockets are not mediated on
  the verified kernels. A sandboxed process can reach services such as the session
  D-Bus, and was shown to have `systemd --user` start an unrestricted process.
  `--status` reports `host_ipc.isolation_enforced: false` in every mode. For that
  isolation, run the agent under a separate user, in a VM or in a container.
- The workspace is granted authority: deletions, `git reset --hard` or a workspace
  `.env` inside it are not protected.
- No aggregate memory or process limits; no destination filtering for `--net all`.
- Not a VM or container. Verified on Linux x86_64 only.

Full list, per mode: [threat model](docs/v2/THREAT_MODEL.md).

## Documentation

- [Architecture](docs/v2/ARCHITECTURE.md): setup order, layers, network, resources, policy format
- [Threat model](docs/v2/THREAT_MODEL.md): guarantees per mode, residual risks, non-goals
- [Test plan](docs/v2/TEST_PLAN.md): what each suite proves and how CI is tiered
- [Walkthrough](docs/v2/WALKTHROUGH.md): the mechanisms in plain language
- [V2 build report](docs/v2/V2_BUILD_REPORT.md): release-candidate summary
- [Documentation index](docs/README.md), including V1 and engineering history

```text
sandbox/    V2 runner (C), tests, agentguard-agent wrapper
redteam/    effect-based attack corpus, V1/V2 drivers, committed results
agentguard/ V1 hooks and policy;  scripts/  hook dispatcher, capability audit
tests/      V1 test suite;        docs/     v2/ reference, v1/, process/ history
```

## License

MIT. See [LICENSE](LICENSE).
