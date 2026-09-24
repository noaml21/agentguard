# AgentGuard V2 Architecture

V2 adds `agentguard-run`, a small C launcher that places a target command and its
whole descendant tree inside kernel-enforced restrictions. V1 hooks stay in place
as the early-feedback / audit / snapshot layer; V2 is the enforcement layer.

```text
agentguard-run [options] -- <command> [args...]
   |
   | parent (supervisor, unrestricted, owns lifecycle)
   |   - refuses EUID 0
   |   - loads + validates policy (opened before fork, from outside the workspace)
   |   - probes kernel capabilities (AVAILABLE)
   |   - resolves REQUESTED layers from policy/flags
   |   - becomes child subreaper; forks
   |   - reads setup report pipe; forwards signals; enforces deadline; reaps tree
   |
   +-- child (setup, then exec)
         pgrp/TTY handoff -> rlimits -> open rule path fds -> mark fds CLOEXEC
         -> no_new_privs -> Landlock restrict_self -> seccomp filter -> execvp
         (any required step fails => write failure record, _exit; target never runs)
```

## Measured environment (Phase 0, 2026-09-24)

Collected by `scripts/capability_audit.sh` (unprivileged; no host changes).

| Fact | Value on development host |
|---|---|
| Distro / kernel / arch | Ubuntu 24.04.5 LTS, `7.0.0-31-generic` (HWE), x86_64 |
| Compiler | GCC 13.3.0; no clang, clang-tidy, cppcheck, valgrind |
| Active LSMs | lockdown, capability, landlock, yama, apparmor, ima, evm |
| Landlock ABI (runtime) | **8**: FS, REFER, TRUNCATE, TCP bind/connect (port), IOCTL_DEV, scoped abstract-unix + signals (ABI 6), later ABI 7–8 features. **Not** available: pathname-unix mediation (ABI 9), UDP (ABI 10) |
| seccomp | filter mode available; actions: kill_process kill_thread trap errno user_notif trace log allow |
| no_new_privs | settable unprivileged |
| libseccomp | headers absent (installing would be a host change) |
| Unprivileged user namespaces | `unshare(CLONE_NEWUSER)` succeeds, but AppArmor `apparmor_restrict_unprivileged_userns=1` denies `uid_map` writes and nested net/pid/mount namespace creation (EPERM) — **namespace tier UNAVAILABLE on this host** |
| Yama ptrace_scope | 1 (ptrace restricted to descendants) |
| cgroup | v2; current scope is user-writable with `cgroup.kill`; user-owned delegated subtree `user@1000.service` with cpu, memory, pids controllers |
| close_range / pidfd_open / subreaper | all available |

The runner re-probes at every start; nothing above is hardcoded.

## Privilege model

- Runs as the invoking unprivileged user. Not setuid, never will be.
- Refuses EUID 0 (including `sudo agentguard-run ...`) with a clear error: as root,
  Landlock and seccomp still apply but root keeps capabilities (e.g. CAP_SYS_ADMIN,
  CAP_DAC_OVERRIDE semantics outside Landlock scope, raw sockets, module loading),
  so the documented guarantees would be wrong. There is no override flag in Core.
- All restrictions are unprivileged: no_new_privs + Landlock + seccomp. Namespaces are
  used only if the host permits them unprivileged (not on the development host).

## Enforcement layers

| Layer | Purpose | Requirement |
|---|---|---|
| no_new_privs | Blocks setuid/file-capability privilege gain; prerequisite for unprivileged Landlock and seccomp | always required |
| Landlock FS | Kernel filesystem access control on inode-bound rules | required by default |
| Landlock net (ABI ≥ 4) | TCP bind/connect restricted **by port only** | required when network mode needs it |
| Landlock scope (ABI ≥ 6) | Blocks signals and abstract-unix connects to processes outside the sandbox domain | required by default when ABI ≥ 6 |
| seccomp-BPF | Denies syscalls outside the coding-agent threat envelope; socket family filter | required by default |
| rlimits | Per-process bounds (core dumps, fsize, etc.) with honest semantics | optional |
| Wall-clock deadline | Tree termination after a timeout | optional |
| cgroup v2 kill | Reliable tree kill incl. setsid escapers, when a writable cgroup exists | optional (reported) |

## Setup order (child, before exec) and why

1. **Process group / TTY handoff** — `setpgid(0,0)`; parent makes the group foreground
   with `tcsetpgrp` when stdin is a TTY. Done first; needs no restricted syscalls.
2. **rlimits** — plain `setrlimit`, before seccomp so the filter need not allow it.
3. **Open Landlock rule paths as `O_PATH` fds** — the kernel resolves each path to an
   inode now; rules bind to that object, not to a string re-resolved later. Opened
   before restrict_self so rule construction cannot be affected by the new domain.
4. **FD sanitation** — `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)` (fallback: iterate
   `/proc/self/fd`), except the report pipe which is already CLOEXEC. Marking CLOEXEC
   (instead of closing) keeps setup fds usable until the atomic close at `execve`.
5. **`PR_SET_NO_NEW_PRIVS`** — must precede `landlock_restrict_self` and seccomp
   filter installation for an unprivileged process (kernel returns EPERM otherwise).
6. **Landlock** — create ruleset for the handled access rights the running ABI supports,
   add rules, `landlock_restrict_self`.
7. **seccomp filter** — last, so the filter never has to permit setup syscalls
   (landlock_*, prctl, close_range); after it only `execve` remains.
8. **`execvp`** — the report pipe closes on success (EOF ⇒ parent knows the target
   started); on any failure the child writes a failure record and `_exit`s.

Invariant: no target code runs before step 8, and step 8 is reached only if every
required layer reported success.

## seccomp implementation choice

To be finalized in Phase 5. Current decision: hand-written classic BPF with
`linux/filter.h` / `linux/seccomp.h`, because libseccomp is not installed and installing
it is a host change, and the Core filter is small (arch check, a short deny list, and
argument checks on `socket` family). The filter must stay readable (macro table, one
rule per line) and be tested deterministically.

## Process lifecycle

- Parent sets `PR_SET_CHILD_SUBREAPER` so orphaned descendants reparent to it.
- Child runs in its own process group; parent forwards SIGTERM/SIGHUP/SIGQUIT (and
  SIGINT when not on a TTY) to that group.
- On a TTY the child group is foreground: Ctrl-C and SIGWINCH go to it directly from
  the kernel; the parent restores the foreground group on exit.
- After the main child exits: SIGTERM to the group, grace period, SIGKILL, then reap
  all reparented descendants.
- Limit (per mode): a descendant that calls `setsid()`/`setpgid()` leaves the group;
  without a cgroup it is still reaped once reparented but may not receive group
  signals. cgroup.kill (when available) closes this gap. Details in Phase 2/7.

## Network modes

Defined in Phase 6. The development host has Landlock TCP (port-only) and no Landlock UDP,
and no namespaces, so there is no destination filtering and no namespace isolation.
