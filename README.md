# AgentGuard

[![CI](https://github.com/noaml21/agentguard/actions/workflows/ci.yml/badge.svg?branch=v2%2Fkernel-sandbox)](https://github.com/noaml21/agentguard/actions/workflows/ci.yml)

**Guardrails and a Linux kernel sandbox for AI coding agents.**

Coding agents run shell commands and edit files with your privileges. AgentGuard puts
two complementary layers around them:

| Layer | What it is | Decides on | Good for |
|---|---|---|---|
| **V1 — workflow guardrails** | Claude Code hooks (`.claude/settings.json`) | the *text* of each tool request | early, explainable feedback; command and file policy; pre-change snapshots; commit policy; audit log |
| **V2 — kernel enforcement** | `agentguard-run`, a small C launcher | the *effect* of every syscall of the agent and all its descendants | denying out-of-workspace file access, IP networking, and same-UID process interference, however the command is spelled |

V1 is guidance for a cooperative agent and can be bypassed by re-spelling a command
(the red-team corpus finds 11 such bypasses in 20 cases). V2 does not read commands at
all: once a process is inside, the kernel refuses the effect.

Status: **V2 release candidate `2.0.0-rc.1`** on branch `v2/kernel-sandbox` (not yet
merged or tagged). Linux only.

## Quick start

```bash
make -C sandbox                       # warning-clean build (-Wall -Wextra -Werror)
make -C sandbox install               # agentguard-run + agentguard-agent -> ~/.local/bin

agentguard-run --status               # what this kernel can enforce
cd ~/src/myrepo
agentguard-run -- bash                # a shell that can write only this directory, no network
agentguard-run --net all --timeout 600 -- make test
agentguard-agent -- claude            # Claude Code inside the sandbox (V1 hooks still run)
```

What that looks like (real output, dev host, disposable directories, fake `HOME`):

```text
$ agentguard-run -- sh -c "echo ok > build.log && cat build.log"
ok
$ agentguard-run -- sh -c "cat ~/.ssh/id_demo"
cat: /…/home/.ssh/id_demo: Permission denied
$ agentguard-run -- python3 -c 'open("../escape", "w")'
PermissionError: [Errno 13] Permission denied: '../escape'
$ agentguard-run -- python3 -c 'import socket; socket.create_connection(("1.1.1.1", 443))'
PermissionError: [Errno 13] Permission denied
$ agentguard-run --status
AgentGuard sandbox status (mode=strict)
  layer            state        required
  no_new_privs     requested    yes
  cgroup_kill      requested    no
  landlock_fs      requested    yes
  landlock_scope   requested    yes
  seccomp          requested    yes
  network          none (socket() limited to AF_UNIX/AF_NETLINK via seccomp)
  …
  host IPC         NOT ISOLATED: pathname Unix sockets can reach unconfined host services
  SysV IPC         denied via seccomp
```

`agentguard-agent` is a ~40-line wrapper that spells out a recipe for coding agents: the
enclosing git repository is the writable workspace, the agent's install directory is
readable, its state files (`~/.claude`, `~/.claude.json`) are writable, and network is on
(`AGENTGUARD_NET=none` turns it off). Everything else in `$HOME` stays unreadable.
Policies can also live in a file (`--policy FILE`) that the sandboxed agent cannot modify.

## How V2 works

```text
agentguard-run [options] -- COMMAND
  |
  +-- supervisor (unrestricted): load + validate policy, probe the kernel, fork,
  |     forward signals, enforce the deadline, kill and reap the whole tree
  |
  +-- child: join owned cgroup -> close inherited fds -> rlimits -> no_new_privs
        -> Landlock filesystem rules -> Landlock scope -> seccomp-BPF -> exec COMMAND
           (any required step fails => the command never runs)
              |
              +-- claude -> V1 hooks, bash, git, gcc, python, node ... (all inherit V2)
```

| Mechanism | Effect |
|---|---|
| **Landlock filesystem** | Read/write only the workspace and explicit `--allow-write` paths; read-only system locations; `$HOME` invisible. Rules bind to inodes, so symlinks, `..`, hard links and renames cannot escape. |
| **Landlock scope** (ABI ≥ 6) | No signals to, and no abstract-Unix connections into, processes outside the sandbox (including the supervisor). |
| **seccomp-BPF** (hand-written, arch-checked) | Denies ptrace/process_vm, namespaces and mounts, bpf, perf, io_uring, kernel modules, SysV IPC, `pidfd_getfd`; `prlimit64` and scheduling setters only for the caller itself; `clone3` → `ENOSYS` so the flag-checked `clone` is used. |
| **no_new_privs** | setuid/file capabilities cannot raise privilege. |
| **Network modes** | `--net none` (default): only `AF_UNIX`/`AF_NETLINK` sockets can be created, so no TCP/UDP/raw IP. `--net all`: host networking. No destination filtering. |
| **Resources and deadline** | Core dumps off; optional per-process file-size/open-file limits; `--timeout` tears down the tree; **opportunistic** `cgroup.kill` also catches `setsid` escapees when a delegated cgroup is available. |
| **Strict policy + integrity** | Line-based `key = value` policy, every oddity an error; policy file and runner must be outside every writable root (checked by inode). |
| **Fail-closed negotiation** | Each layer is reported available / requested / applied. Strict mode (default) refuses to run unless every required layer applies; `--degraded` runs and lists exactly what is missing. |
| **Honest status** | `--status [--json]` reports layers, network enforcement, resources, and `host_ipc.isolation_enforced: false`. |

## What V2 does not claim

- **Not a VM or container.** Same kernel, same UID, no namespaces on the measured hosts.
- **No complete same-UID host-service isolation.** Pathname Unix sockets are not mediated
  on the verified kernel ABI: a sandboxed process can still talk to host services such as
  the session D-Bus, and was shown (historically) to ask the user's systemd to start an
  unrestricted process. Status reports this in every mode. If you need that isolation, run
  the agent as a separate user, in a VM, or in a container — and AgentGuard inside it.
- **Nothing inside the workspace is protected.** Deleting files, `git reset --hard`,
  reading a workspace `.env`, or editing V1 hook files there are allowed by design.
- **No aggregate resource limits** (memory, process count) and **no destination-filtered
  networking**.

Full list: [threat model](docs/v2/THREAT_MODEL.md) §4–6.

## Evidence

All tests run unprivileged on disposable fixtures; oracles check real effects (bytes,
arrivals, process liveness), not just exit codes.

| Suite | Command | Result |
|---|---|---|
| V1 hook regression | `./tests/run_tests.sh` | 40/40 |
| V1 red-team corpus | `python3 redteam/run_v1.py` | 20 cases: 7 prevented, 11 bypasses, 2 legitimate |
| V2 integration (11 suites) | `make -C sandbox check` | 226/226 on the dev host; CI: 220 passed + 6 delegated-cgroup cases skipped with reason |
| V2 under ASan + UBSan (fatal) | `make -C sandbox check-asan` | 226/226, no reports (CI: same 220 + 6 skipped) |
| V1 vs V2 comparison | `python3 redteam/run_v2.py` | 36 cases: **0 unexpected**; 17 prevented by the V2 boundary (every V1 bypass that targets something outside the workspace), 14 allowed inside granted workspace authority, 4 legitimate, 1 out of scope |

Comparison matrix: [`redteam/results/comparison.md`](redteam/results/comparison.md).
CI runs every tier on GitHub-hosted Ubuntu 24.04; kernel-dependent tiers run only when
the runner provides every required layer and otherwise are reported as skipped, never
as passed. Details: [test plan](docs/v2/TEST_PLAN.md).

**Supported environment.** Linux x86_64 (aarch64 compiles; untested). Strict mode needs
Landlock ABI ≥ 6 (kernel ≥ 6.12) and seccomp; older kernels can use `--degraded` with
the missing guarantees reported. Developed and verified on Ubuntu 24.04.5, kernel 7.0
(Landlock ABI 8), GCC 13.

## Documentation

- [Documentation index](docs/README.md)
- [Architecture](docs/v2/ARCHITECTURE.md) — setup order, layers, network, resources, policy, V1/V2 integration
- [Threat model](docs/v2/THREAT_MODEL.md) — guarantees per mode, residuals, non-goals, host-IPC inventory
- [Test plan](docs/v2/TEST_PLAN.md) — every suite and what it proves
- [Walkthrough](docs/process/WALKTHROUGH.md) — plain-language explanation of the mechanisms
- [V2 build report](docs/v2/V2_BUILD_REPORT.md) — release-candidate summary
- [V1 threat model](THREAT_MODEL.md) — the hook layer's boundaries

## Repository layout

```text
sandbox/            V2: agentguard-run (C, src/ include/), tests/, scripts/agentguard-agent
redteam/            effect-based corpus, V1 and V2 drivers, committed results
agentguard/         V1 hooks, shared library, policy configuration
scripts/            V1 hook dispatcher, capability audit
tests/run_tests.sh  V1 regression suite
docs/               architecture, threat model, test plan, process log
```

## V1 hooks in brief

Claude Code sends PreToolUse/PostToolUse requests through `scripts/run_hook_chain.sh`,
which runs a fixed, fail-closed chain: command firewall → rate limiter → commit policy
for Bash; file/workspace policy → pre-change snapshot for Edit/Write; a syntax check
after writes; a SessionEnd summary from the JSONL audit log. Requirements: bash, jq,
flock, GNU coreutils, Python 3, GCC, Git. See [THREAT_MODEL.md](THREAT_MODEL.md).
