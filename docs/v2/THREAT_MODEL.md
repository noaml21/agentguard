# AgentGuard V2 Threat Model

Claim tags: **IMPLEMENTED** (code exists), **VERIFIED** (test evidence on a named host),
**ASSUMED** (relied on, not tested), **UNAVAILABLE** (host/kernel lacks it),
**DEGRADED** (weaker in the named mode). Every claim is scoped to a mode.

## 1. Why V1 is insufficient

V1 (see the [V1 threat model](../v1/THREAT_MODEL.md)) inspects tool-request *text*: a regex firewall for Bash
commands and a canonical-path check for Read/Edit/Write. Its own threat model states
the limits: equivalent effects can be written through interpreters, indirection,
variable expansion, alternate programs, and symlinks; a Bash command bypasses the
Read/Edit/Write file policy entirely; path checks have a TOCTOU window. Phase 1 measures
these gaps with an effect-based corpus (`redteam/`).

V2 moves enforcement into the kernel so that the *effect* is denied regardless of how
the request was spelled.

## 2. Adversary

A coding agent (or code it runs) executing as the invoking user inside
`agentguard-run`, with arbitrary control of the target command and all descendants.
It may be confused or deliberately hostile. It cannot load kernel modules or exploit
the kernel (non-goal).

## 3. Assets

- Files outside the writable workspace (home directory, credentials, other repos).
- AgentGuard's own policy, binary, hooks, and configuration used by future runs.
- Other same-UID processes and user services (signals, sockets, ptrace).
- Network egress.
- Host availability (bounded by resource limits, per mode).

## 4. Guarantees per mode

Filled in as phases complete. "Dev host" = Ubuntu 24.04.5, kernel 7.0.0-31, Landlock ABI 8.
Every row below is subject to the **host-IPC residual** in §4.1.

| Property | strict (unprivileged baseline) | degraded (explicit) | enhanced (namespaces) |
|---|---|---|---|
| Target never runs before enforcement | VERIFIED (Phase 3 contract tests) | missing layers listed; apply failures still refuse | — |
| No privilege gain via setuid | VERIFIED (no_new_privs applied) | only if no_new_privs applied | — |
| Filesystem reads/writes outside the policy denied | VERIFIED (Landlock, Phase 4 matrix) | only if Landlock applied | UNAVAILABLE on dev host |
| ptrace / process_vm_* / namespace creation+join / mount (incl. new mount API) / module / kexec / bpf / perf / io_uring denied | VERIFIED (seccomp, Phases 5–6) | only if seccomp applied | — |
| `--net none`: no IP (v4/v6 TCP, UDP, raw) or other non-local socket can be created | VERIFIED (socket-family allowlist; effect tests with loopback listeners) | NOT enforced if seccomp missing — reported in status + warning | UNAVAILABLE on dev host |
| `--net all`: host networking; no destination filtering | by design | same | — |
| Core dumps disabled; optional per-process file-size / open-file bounds | VERIFIED (rlimits, Phase 7; per process, not aggregate) | same | — |
| Wall-clock deadline starts tree teardown | VERIFIED (Phase 2 + Phase 7 escapee case); killing setsid escapees depends on cgroup_kill below | same dependency | — |
| setsid/setpgid escapers killed at teardown | VERIFIED on dev host when `cgroup_kill` applied (host-only; opportunistic) | pgid-only teardown when unavailable — escapers survive (VERIFIED) | — |
| Aggregate process-count / memory limits | UNAVAILABLE in Core (needs controllers in a cgroup AgentGuard does not own) | — | — |
| Malformed policy never runs the target | VERIFIED (Phase 8, 37 malformed-input cases) | same | — |
| Target cannot alter the policy used by the next run | VERIFIED in policy mode (location check + Landlock; 17 attack spellings leave bytes/inode/listing unchanged) | requires Landlock FS applied | — |
| Target cannot replace the runner binary for the next run | VERIFIED in policy mode (refused if inside a writable root); CLI mode: DEGRADED — only reported in status | requires Landlock FS applied; same CLI limitation | — |
| Same-UID signals to outside processes (incl. the supervisor) | VERIFIED (Landlock `SCOPE_SIGNAL`, layer `landlock_scope`, ABI ≥ 6; `kill`, SIGTERM, `pidfd_send_signal`, grandchild → EPERM, disposable sentinel alive; Phase 9). `tgkill`/`rt_sigqueueinfo`/SIGIO use the same kernel hook — ASSUMED, not individually tested | layer reported `missing`; VERIFIED that a degraded run can then reach the sentinel | — |
| Abstract AF_UNIX to outside listeners | VERIFIED (Landlock `SCOPE_ABSTRACT_UNIX_SOCKET`, same layer: target and descendant get EPERM, outside listener logs 0 hits; abstract sockets *inside* the sandbox still work) | layer reported `missing` | — |
| Resource limits of outside same-UID processes | VERIFIED (seccomp: `prlimit64` only with pid 0; sentinel limits unchanged; self `ulimit`/`setrlimit` work; an explicit own pid is denied too) | only if seccomp applied | — |
| Same-UID ptrace / process_vm / sensitive proc access | VERIFIED against an outside disposable sentinel: seccomp independently denies attach and process_vm read/write; Landlock independently denies those plus `/proc/PID/mem` read/write and reopening `/proc/PID/fd/N`. Positive controls succeed after the sentinel opts itself into tracing. Yama is not credited | without both Landlock domains, proc access succeeds; without seccomp, Landlock still protects the outside sentinel | — |
| SysV shared memory, semaphore and message-queue access | IMPLEMENTED syscall deny-list; VERIFIED attach/write, semaphore SETVAL and message send denied, fixture state unchanged | VERIFIED effects succeed with seccomp omitted; status reports `sysv_denied:false` | — |
| **Pathname AF_UNIX to same-UID host services (session D-Bus, `systemd --user`)** | **NOT ISOLATED — accepted residual, outside V2 Core** (§4.1). Historical VERIFIED escape; no mechanism applied mediates pathname AF_UNIX; status reports `host_ipc.isolation_enforced:false`. No guarantee in this table holds against a target that uses such a service | same | — |

### 4.1 Known residuals (current)

- **Same-UID host-service IPC — NOT ISOLATED, all modes (accepted residual, Phase 9
  scope decision).** Pathname AF_UNIX connects to same-UID host services are not mediated
  at Landlock ABI 8 (pathname-unix mediation needs ABI 9). Abstract-unix and signal scoping
  (Phase 9) do not cover pathname sockets, and no mechanism enabled after the evidence
  below mediates them. **Historical VERIFIED evidence (Phase 6, 2026-09-25, dev host):** a
  process inside `--net none` asked the user systemd manager (`systemd-run --user`, over
  `/run/user/1000/bus`) to start a process; that process had `Seccomp: 0`,
  `NoNewPrivs: 0`, and could create `AF_INET` sockets — outside every V2 layer. That
  experiment was deliberately **not re-executed** at the final Phase 9 head (it contacts a
  real host service); since nothing added afterwards mediates the path, it is treated as
  still applicable. Same-host daemons can also relay traffic (e.g. DNS via
  systemd-resolved). **Scope of every V2 guarantee:** they hold against an adversary that
  does not obtain authority from same-UID host services reachable over pathname AF_UNIX.
  This includes the Phase 8 integrity rows: an unconfined process started this way can
  rewrite the policy file and the runner binary. `strict` means every *required* V2
  mechanism applied, not complete host isolation; status reports
  `host_ipc.isolation_enforced:false` and `pathname_unix:"unrestricted"` in every mode.
  Users who need complete same-UID host-service isolation need a stronger boundary outside
  V2 Core (a separate UID without a user session, a VM, or a container with its own user
  services and no access to the host's `$XDG_RUNTIME_DIR`).
- **clone3**: flags are unfilterable (struct in user memory); mitigated by returning
  `ENOSYS` so callers fall back to the flag-filtered `clone()`. A program that *requires*
  clone3 (no fallback) fails; none observed (glibc, python, git, gcc tested).
- **`fsopen`/`fsconfig`/`fsmount`, `CLONE_NEWNET`, `syslog`**: already `EPERM` for an
  unprivileged process on the dev host (no caps; `dmesg_restrict=1`), so their seccomp
  rules are belt-and-suspenders and the tests do not independently prove them there.
- **No destination filtering** in any mode; `--net all` is full host networking.
- **Resources are not an availability guarantee.** rlimits bound each process
  individually; a fork-heavy or many-file workload can still exhaust host memory, PIDs, or
  disk. The cgroup tier kills, it does not limit. Processes started through the host-IPC
  escape above are outside the owned cgroup.
- **`prlimit64`**: closed in Phase 9 (seccomp allows only pid 0). Before the rule, the
  sandbox set an outside sentinel's `RLIMIT_NOFILE` to 77 (read back outside); the same test
  now leaves it unchanged. Trade-off: `prlimit(getpid(), …)` by explicit pid is also EPERM.
- **Phase 9 baseline probe (2026-09-26, dev host; before the Phase 9 layers — historical)**, from inside `agentguard-run --net none`
  against disposable outside fixtures: `kill(outside, 0)` permitted; `pidfd_open` +
  `pidfd_send_signal(…, 0)` permitted; abstract-unix connect to an outside listener
  succeeded (listener logged the hit); connect to `/run/user/<uid>/bus` succeeded.
  A standalone program applying Landlock `scoped = ABSTRACT_UNIX_SOCKET | SIGNAL` on the
  same kernel got `EPERM` for both the kill and the abstract connect while `socketpair`
  still worked — so those two surfaces have an available kernel mechanism; pathname
  AF_UNIX (the D-Bus escape) does not.

## 5. Non-goals

- Kernel compromise or kernel bugs.
- Damage inside the writable workspace that the policy intentionally permits.
- Vulnerabilities in binaries the policy allows the agent to run.
- Destination/host-level network filtering (Landlock is port-only; no proxy in Core).
- Network-namespace isolation (namespace tier unavailable on the dev host).
- Guarantees that the active mode reports as unavailable or degraded.
- Running as root.
- Complete same-UID host isolation: pathname AF_UNIX services (session D-Bus,
  `systemd --user`, agents/daemons listening in `$XDG_RUNTIME_DIR`), user-to-user netlink,
  process metadata visibility, and shared default grants (`/tmp`, `/dev/shm` reads,
  `/dev/pts`). See §4.1 and §6.

## 6. Phase 9 surface inventory and decision (2026-09-27, closed 2026-10-02)

Phase 9 is **COMPLETE** against its PLAN gate ("each surface is Core / non-goal /
degraded, with fixture evidence"): every surface below carries one of those
classifications and disposable-fixture evidence. Per the PLAN scope rule the claim was
weakened rather than extended: pathname AF_UNIX host services are classified
**not isolated / degraded** in all modes and V2 does not claim complete same-UID
host-service isolation. `strict` means required layers apply; it does **not** mean complete
same-UID host isolation. Status explicitly reports `host_ipc.isolation_enforced:false`
in strict and degraded modes, and the text report says `NOT ISOLATED`.

| Surface | Classification / mechanism | Disposable fixture evidence and limits |
|---|---|---|
| Outside signals and abstract Unix sockets | Core: Landlock scope | Existing 27-case suite: outside sentinel survives; outside abstract listener receives no connection; inside IPC works. Other signal entry points remain ASSUMED as specified above |
| Outside ptrace, process_vm read/write | Core: seccomp and Landlock independently | Extended suite: tracing enabled on the sentinel itself via PR_SET_PTRACER_ANY, no Yama setting changed. Baseline reads/writes succeed; each independent AgentGuard arm denies; sentinel memory unchanged |
| `/proc/PID/mem`, `/proc/PID/fd/N` | Core: Landlock domain relationship | Baseline and no-Landlock control succeed; Landlock-only and normal arms deny. seccomp alone does not protect these opens |
| `/proc/PID/status` metadata | Non-goal: process visibility is not PID namespace isolation | Fixture status remains readable. No claim that metadata, process names or PIDs are hidden |
| prlimit on outside PIDs | Core: seccomp pid=0 only | Existing external limit-value oracle; explicit own PID also denied |
| Outside scheduling / nice / I/O priority | Core: seccomp self-only setters | Slice 3: unconfined and disabled-seccomp arms change a private sentinel's nice, affinity, BATCH policy and I/O priority; protected arm leaves all values unchanged. Group selectors target only a sentinel's private process group. sched_setparam is denied too, but unprivileged priority 0 is a no-op, so that case is return-code evidence only |
| Pathname Unix STREAM/DGRAM/SEQPACKET, including socketpair DGRAM sendto | **DEGRADED — not isolated**, all modes; reported `pathname_unix:"unrestricted"` | Fresh outside listeners receive fixture bytes in both net modes. Test-only socket/socketpair filter prevents every tested arrival but breaks `multiprocessing.Manager`; it is NOT installed by the runner |
| Session D-Bus / user systemd authority | **DEGRADED — not isolated; historical VERIFIED ESCAPE**, all modes; outside V2 Core (§4.1, §5) | Phase 6 experiment (2026-09-25) is the evidence; it was not re-executed at the final Phase 9 head by design, and no later mechanism mediates the path. Synthetic pathname fixtures above show the transport is still reachable |
| Inherited Unix socket and pidfd | Core sanitation for non-kept fds; explicit delegation for stdio/keeps | Non-kept fds return EBADF and peer gets no data. `--keep-fd` socket transmits fixture bytes; kept pidfd cannot signal outside scope. All 64 explicit keeps now survive (off-by-one fixed) |
| SysV IPC | Core deny via seccomp, DEGRADED without it | Fresh IPC_PRIVATE shm/sem/msg objects only; disabled-seccomp control mutates each, normal target gets EPERM and external bytes/value/queue contents stay unchanged. Creation/control/operation syscalls denied; shmdt remains allowed. SysV applications lose compatibility |
| POSIX shared memory / mmap | **DEGRADED by filesystem grants**, not a separate IPC namespace | Fresh `/dev/shm` fixture is readable under default `/dev` read grant; writable open denied and bytes unchanged. No confidentiality claim for allowed read roots. Explicit write grants delegate shared-state authority |
| POSIX named message queues | Core: measured Landlock protection under current policy/ABI | Exclusively created queue: baseline sends/receives; sandbox opens for send/receive denied, outside queue contents preserved. Disabling seccomp retains denial; disabling both Landlock domains permits effects. This is not IPC-namespace isolation or evidence for every queue operation/policy |
| User-to-user AF_NETLINK | **DEGRADED / OPEN**, allowed family in net none | NETLINK_USERSOCK message arrives at a freshly bound outside fixture port in both baseline and sandbox. No kernel-control endpoint is contacted. “Local” does not mean isolated; kernel permissions on privileged netlink operations are host policy |
| TTY / `/dev/pts`, device ioctls | **DEGRADED**, compatibility grants; no tty isolation claim | Reopening a new fixture pty slave and writing reaches its master. TIOCSTI on that fixture returns EIO in both baseline and sandbox on this host: host/kernel policy, NOT AgentGuard enforcement. IOCTL_DEV remains unhandled |
| Writable files/FIFOs/shared scratch | Intentional policy delegation, not an IPC boundary | Phase 4 read/write matrix applies; default `/tmp` is shared writable authority, not private scratch. Existing file/pipe runner tests plus explicit keep tests cover inherited authority |

The blanket AF_UNIX-denial candidate preserves socketpair streams, asyncio, pipe-based
multiprocessing, gcc, git, Node child_process and `claude --version` in fixtures. Localhost
NSS lookup completes and the syslog API returns when AF_UNIX creation is denied (no real
nscd/syslog service is contacted; this is fallback behavior, not successful logging).
But `multiprocessing.Manager` fails with PermissionError, whereas it works with the normal
runner. Decision: do not impose blanket denial on ordinary developer runs; use the
canonical report-the-missing-guarantee fallback. There is no released Unix-denial mode or
claim that the test-only candidate is a complete security boundary. In particular it does
not revoke kept sockets, fix netlink, or verify the real D-Bus path.

The [kernel's Landlock ptrace documentation](https://docs.kernel.org/7.0/userspace-api/landlock.html#ptrace-restrictions)
describes the domain relationship underlying the memory tests. Evidence here is the
fixture effects, not an assumption that host Yama/AppArmor policy provides our boundary.
Scheduling and POSIX queue fixtures were added in slice 3. The scheduling setters allow
only pid zero; setpriority/ioprio_set also require the single-process selector. Explicit
PIDs/TIDs (even inside the sandbox) and group/UID selectors are denied. `nice`, `taskset`,
`chrt`, `ionice` command launches and self-directed APIs are tested; libraries that pin
other threads by explicit TID may need a future design. Untested same-UID APIs are not
covered by these results; no exhaustive host-isolation guarantee is made.
