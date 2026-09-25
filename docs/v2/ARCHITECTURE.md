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
| Landlock net (ABI ≥ 4) | TCP bind/connect restricted **by port only** | not used in Core (see Network modes) |
| Landlock scope (ABI ≥ 6) | Blocks signals and abstract-unix connects to processes outside the sandbox domain | planned (Phase 9); **not applied yet** |
| seccomp-BPF | Denies syscalls outside the coding-agent threat envelope; clone-flag filter; socket family filter (`--net none`) | required by default |
| rlimits | Per-process bounds: core=0 always; `--max-file-size`, `--max-open-files` | core always; others on request |
| Wall-clock deadline | Tree termination after `--timeout` (lifecycle, Phase 2) | on request |
| cgroup v2 kill (`cgroup_kill` layer) | Owned child cgroup + `cgroup.kill`: tree kill incl. setsid escapers | opportunistic: used when available, never required; reported |

## Setup order (child, before exec) and why

0. **Join owned cgroup** (Phase 7, when `cgroup_kill` is requested) — write `0` to the
   pre-opened `cgroup.procs` before anything else (FD sanitation would close that fd); the
   `cgroup_kill` layer later reports the outcome.
1. **Process group / TTY handoff** — `setpgid(0,0)`; parent makes the group foreground
   with `tcsetpgrp` when stdin is a TTY. Needs no restricted syscalls.
2. **rlimits** — plain `setrlimit` (implemented just after FD sanitation), before
   Landlock/seccomp; a failure refuses the run.
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

## seccomp implementation choice (Phase 5, decided)

Options compared:

| | libseccomp | hand-written classic BPF |
|---|---|---|
| Security | mature, well-audited rule compiler | small surface, but we own correctness |
| Dependency/portability | needs `libseccomp-dev` — **absent here**, installing it is a host change | none; only kernel UAPI headers |
| Readability | high-level API | low-level, but our filter is a flat deny-list |
| Testability | same (effect tests) | same |
| Maintenance | external version coupling | a single ~80-line table we control |

**Decision: hand-written classic BPF.** libseccomp headers are not installed and adding
them is a host change; the Core filter is intentionally small — an arch/x32 guard plus a
flat deny-list built at runtime from a `SYS_*` table (two BPF instructions per entry). This
keeps the whole filter readable in one file and adds no dependency. If the deny-list ever
grew into argument-heavy, arch-specific rules, libseccomp would become the better trade.

The filter is **default-allow with a targeted deny-list** (returns `EPERM`), not
default-deny: a coding agent runs a huge, open-ended set of ordinary syscalls, so an
allow-list would be brittle and constantly break real work, while the isolation-relevant
dangerous syscalls are a short, stable set. Landlock (not seccomp) is the primary
filesystem boundary; seccomp closes same-UID/escape vectors Landlock does not cover.
Installed **last** (after Landlock) so the filter never has to permit setup syscalls.

## Process lifecycle

- Parent sets `PR_SET_CHILD_SUBREAPER` so orphaned descendants reparent to it.
- Child runs in its own process group; parent forwards SIGTERM/SIGHUP/SIGQUIT (and
  SIGINT when not on a TTY) to that group.
- On a TTY the child group is foreground: Ctrl-C and SIGWINCH go to it directly from
  the kernel; the parent restores the foreground group on exit.
- After the main child exits: SIGTERM to the group, grace period, SIGKILL, then reap
  all reparented descendants.
- Limit (per mode): a descendant that calls `setsid()`/`setpgid()` leaves the group;
  without a cgroup it does not receive group signals and survives the runner. With the
  `cgroup_kill` layer applied, teardown writes `cgroup.kill` and it dies (VERIFIED, Phase 7).

## Network modes (Phase 6, implemented)

`--net none|all`, default `none`. The development host has Landlock TCP (port-only), no
Landlock UDP (ABI 10), and no usable namespaces, so AgentGuard offers **no destination/IP
filtering and no network-namespace isolation**. The one strong unprivileged primitive is a
seccomp filter on `socket()`'s address-family argument, which gives all-or-nothing IP
networking:

| Mode | Mechanism | Effect |
|---|---|---|
| `none` (default) | seccomp: `socket()` allowed only for `AF_UNIX` and `AF_NETLINK`; every other family → `EACCES` | No TCP/UDP/raw IP (v4 and v6), no `AF_PACKET`, `AF_VSOCK`, … . Allowlist, so an unanticipated family is denied. AF_UNIX local IPC and netlink queries (interface lists; cannot carry traffic off-host) work. |
| `all` | no network rule | Host networking as the invoking user (intended for `-- claude`, which needs its API). Other layers unchanged. |

- Enforcement point is socket *creation*, so it covers every protocol and every spelling
  (python, bash `/dev/tcp`, compiled code) and is inherited by all descendants. `io_uring`
  (whose `IORING_OP_SOCKET` would bypass per-syscall seccomp) is denied in every mode.
- There is no `socketcall(2)` on x86_64/aarch64, and the arch guard kills foreign-ABI
  syscalls, so there is no alternate entry point to `socket()`.
- `none` depends on the seccomp layer. In strict mode seccomp is required, so an
  unavailable seccomp refuses the run. In explicit `--degraded` mode the run proceeds but
  `--status` reports `"network":{"mode":"none","enforced":false}` and every run prints a
  warning; `none` is never silently downgraded.
- Landlock TCP port rules (PLAN 6.2) are **not used** in Core: port-only TCP filtering
  without UDP coverage cannot express a truthful intermediate mode on ABI 8. Deferred.
- **Residual (VERIFIED on the dev host, all modes):** AF_UNIX connections to same-UID host
  services are not mediated (Landlock pathname-unix control needs ABI 9; abstract-unix
  scoping is not applied yet). From inside `--net none`, `systemd-run --user` over the
  session D-Bus socket started a process with `Seccomp: 0`, `NoNewPrivs: 0` and working
  `AF_INET` sockets, i.e. **outside every AgentGuard layer**. Same-host services may also
  relay traffic (e.g. systemd-resolved DNS). This is the Phase 9 host-IPC surface; until it
  is closed, no V2 guarantee holds against an adversary that uses it.

`--status` (text and `--json`) reports the requested network mode and whether it is enforced.

## Resource limits (Phase 7, implemented)

Nothing here is an aggregate resource guarantee except where stated. rlimits are
**per process**: each descendant inherits its own copy, so N processes may each use the
full amount.

| Limit | Kernel primitive | Scope | Inheritance / after fork | Effect | When unavailable |
|---|---|---|---|---|---|
| Core dumps | `RLIMIT_CORE` = 0, soft = hard | per process | inherited; cannot be raised (hard limit, no CAP_SYS_RESOURCE) | prevents core files (dumps can hold secrets). With Ubuntu's piped `core_pattern` the kernel still starts apport, which honors a 0 limit — ASSUMED, not tested | setrlimit failure refuses the run |
| `--max-file-size N` | `RLIMIT_FSIZE`, soft = hard | per process, per file | inherited; cannot be raised | a write past N bytes fails (`SIGXFSZ`, default action terminates; `EFBIG` if ignored). **Not a disk quota**: many files/processes can still fill the disk | same |
| `--max-open-files N` (N ≥ 16) | `RLIMIT_NOFILE`, soft = hard | per process | inherited; cannot be raised | open/socket/pipe past N fails `EMFILE` | same |
| `--timeout S` | parent monotonic deadline (Phase 2 lifecycle; no second timer) | whole tree | n/a | limits wall-clock time: SIGTERM group → 2 s grace → `cgroup.kill` + SIGKILL group → reap; exit 124 | always available |
| tree kill | cgroup v2 `cgroup.kill` on an owned child cgroup | aggregate (every process in the cgroup) | children are created in the cgroup; Landlock makes cgroupfs unwritable, so the target cannot migrate out | kills setsid/setpgid escapers at teardown/timeout | layer `cgroup_kill` reported `unavailable`; teardown falls back to process group + subreaper reaping, where setsid escapers survive |
| process count / memory | — | — | — | **UNAVAILABLE in Core** | reported as `aggregate_limits: "unavailable"` |

Not used, deliberately: `RLIMIT_NPROC` counts every process of the real UID system-wide
(inside and outside the sandbox), so it is neither a sandbox cap nor safe to set;
`RLIMIT_AS`/`RLIMIT_CPU` are per-process and would be misread as tree limits.

**cgroup tier design.** The parent reads its cgroup from `/proc/self/cgroup` (v2 only,
`statfs` magic checked), and the layer is available when that directory and its
`cgroup.procs` are writable and `cgroup.kill` exists. Per run it `mkdirat`s
`agentguard-run.<pid>` (fails on `EEXIST`, so it never adopts a directory it did not
create) and opens its `cgroup.procs`/`cgroup.kill`. The child writes `0` to `cgroup.procs`
as its very first action, before FD sanitation and before any target code, so every
descendant is created inside. After teardown the directory is removed. Only the owned
directory is written: no controllers are enabled and no other process is moved.

**Why no aggregate pids/memory limits.** Setting `pids.max`/`memory.max` on the owned
cgroup requires the controllers to be enabled in the *parent's* `cgroup.subtree_control`.
On the dev host the parent is the terminal's `vte-spawn-….scope`: user-owned, with `memory
pids` available but not delegated to children, and holding 11 unrelated processes. Changing
it would modify a cgroup AgentGuard does not own, and the cgroup v2 no-internal-process rule
rejects it anyway. Users who need aggregate limits can start the runner inside a systemd
scope that sets them (`systemd-run --user --scope -p TasksMax=… -p MemoryMax=…
agentguard-run …`); systemd enforces that, not AgentGuard.

## seccomp argument filters (Phase 6 additions)

The Phase 5 deny-list stays flat; Phase 6 added three small hand-computed blocks after it:

1. `clone3` → `ENOSYS`. Its flags live in a user-memory struct seccomp cannot read. glibc
   (`pthread_create`, `posix_spawn`) and other runtimes treat `ENOSYS` as "old kernel" and
   fall back to `clone()`.
2. `clone()` with any `CLONE_NEW*` bit (`NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET`,
   mask `0x7E020000`) → `EPERM`. `fork`/threads pass (no namespace bits). Together with the
   existing `unshare`/`setns` denials and (1), no namespace can be created or joined via these
   syscalls; `CLONE_NEWTIME` is only expressible through `clone3`/`unshare`.
3. `socket()` family allowlist in `--net none` (above).

New deny-list entries: `fsopen`, `fsconfig`, `fsmount` (new mount API), `pidfd_getfd`
(steal an fd from another same-UID process), `syslog` (kernel log), `io_uring_setup/enter/
register` (io_uring operations bypass per-syscall filtering).
