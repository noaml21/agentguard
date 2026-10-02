# AgentGuard V2 Walkthrough

Plain-language explanation of the mechanisms that matter most. Updated as they are built.

## The core idea

V1 reads the *text* of what an agent asks to do and guesses whether it is dangerous.
That fails as soon as the same effect is spelled differently (`python -c`, `$(...)`, a
symlink). V2 asks the kernel to refuse the *effect*: once `agentguard-run` restricts a
process, every program it starts inherits the same restrictions, and no spelling of a
command changes what the kernel allows.

## Why the setup order matters

The child process builds its own cage and then `exec`s the target. The order is forced by
Linux rules:

- **no_new_privs first** (before Landlock and seccomp): the kernel refuses unprivileged
  `landlock_restrict_self` and seccomp filters otherwise, because a setuid program could
  be tricked by restrictions it did not expect. With no_new_privs, `exec` can never grant
  more privilege, so self-restriction is safe.
- **Open rule paths before restricting**: Landlock rules are attached to an opened file
  descriptor, meaning an inode. We open the directories while unrestricted, so the rule
  refers to the object we validated, not a name that could later point elsewhere.
- **seccomp last**: the filter blocks syscalls. Installing it last means it never has to
  allow the syscalls we use during setup.
- **Close non-kept fds before setup**: after the cgroup join, inherited descriptors
  are closed. Only stdio, explicit keeps and the report pipe survive sanitation.
  The report pipe is CLOEXEC, so `execve` closes it atomically when the target starts.

Rejected alternative: have the *parent* restrict itself and then fork. That would restrict
the supervisor, which must stay unrestricted to kill and reap the tree and read its own
state.

## Why capability detection is not enforcement

The kernel supporting Landlock does not mean the sandbox applied it. The runner reports
three separate things for each layer: available (kernel supports it), requested (policy
needs it), applied (setup call succeeded). The target runs only if every required layer
is applied.

## FD sanitation (Phase 2)

An open descriptor is authority. If the agent inherits an fd pointing at a file,
socket, or pipe outside the sandbox, no filesystem or network rule can take that
authority away — the object is already open. So in the forked child, before exec,
`fdsan_apply` closes every descriptor except stdin/stdout/stderr, any explicitly
`--keep-fd` descriptors, and the internal report pipe. It prefers `close_range()`
(one syscall over the gaps between kept fds) and falls back to scanning
`/proc/self/fd`. Kept descriptors have `FD_CLOEXEC` cleared so they survive exec;
the report pipe keeps `FD_CLOEXEC` so it closes exactly at `execve` — its EOF is how
the supervisor learns the target started successfully.

## Process lifecycle and reaping (Phase 2)

The supervisor forks one child, which puts itself in a new process group and execs
the target. The supervisor:

- sets `PR_SET_CHILD_SUBREAPER` so a descendant that outlives its parent reparents to
  the supervisor instead of to init, and can therefore be reaped;
- blocks the managed signals and reads them through a `signalfd`, so signal handling
  and the wall-clock deadline are one `poll()` loop with no async-signal-unsafe work;
- forwards SIGTERM/SIGINT/SIGHUP/SIGQUIT and SIGWINCH to the child's process **group**;
- on the deadline, or after the main child exits, sends SIGTERM to the group, waits a
  grace period, then SIGKILL, reaping every descendant.

Per-mode limit (documented, not hidden): a descendant that calls `setsid()` leaves the
group and no longer receives these group signals. Without a cgroup it is still reaped
once it reparents to the subreaper, but it may not be *signalled*. Phase 7's cgroup
`cgroup.kill` closes this gap where a delegated cgroup is available.

## Why the supervisor stays unrestricted

Only the child restricts itself. The supervisor must remain able to signal and reap the
whole tree and restore the terminal, so it never installs Landlock/seccomp on itself.

## Landlock filesystem ruleset (Phase 4)

Landlock is default-deny *per handled access right*. `ll_restrict_fs` creates a ruleset
declaring the filesystem rights it will enforce (execute, read, write, remove, make-*,
plus REFER on ABI≥2 and TRUNCATE on ABI≥3 — chosen from the runtime ABI, not hardcoded),
then adds `path_beneath` rules:

- read+execute on the default system locations (`/usr`, `/lib*`, `/etc`, `/proc`, `/dev`, …)
  and any `--allow-read` paths, so ordinary programs run;
- full read+write+manage on the `--workspace` root and any `--allow-write` paths;
- read+write on a small set of device nodes (`/dev/null`, tty, pts, urandom, …).

Every rule is added against an `O_PATH` descriptor opened while still unrestricted, so the
rule binds to a concrete **inode**. That is the path-integrity guarantee: a symlink or a
later path swap cannot redirect enforcement, because the kernel resolves the real object at
access time and compares it to the inode-bound rules — not to the string we checked.
`landlock_restrict_self` then applies the ruleset to the process and, by inheritance, to
every descendant, so `python -c`, `sh -c`, and grandchildren are all bound identically.

We deliberately do **not** handle IOCTL_DEV (ABI≥5): restricting device ioctls would break
the inherited interactive TTY, and it is a hardening extra outside the Core FS guarantee.

Dependency note: `landlock_restrict_self` requires `no_new_privs` for an unprivileged
process, which is why `no_new_privs` is layer 0 and applied first. In degraded mode we relax
required layers that are *unavailable*, but a layer that is available yet *fails to apply*
still fails closed — so forcing `no_new_privs` off also refuses Landlock rather than running
with a broken cage.

## seccomp-BPF filter (Phase 5)

seccomp is installed **last**, after Landlock, so the filter never has to permit the
setup syscalls (landlock_*, prctl, close_range). It is a hand-written classic-BPF program
built at runtime: load `seccomp_data.arch` and kill if it isn't the arch we compiled for
(this blocks `int 0x80` / wrong-ABI syscall-number confusion), reject the x86_64 x32 ABI,
then walk a deny-list — two instructions per entry (`if nr == X return EPERM`) — and default
to allow.

It is **default-allow**, not default-deny: a coding agent legitimately uses a vast,
open-ended set of syscalls, so an allow-list would break real work constantly. Landlock is
the filesystem boundary; seccomp's job is to close the same-UID and escape vectors Landlock
does not cover — `ptrace`/`process_vm_*` (inspect or modify other processes), namespace and
mount manipulation (`unshare`, `setns`, `mount`, `pivot_root`, `chroot`, …), kernel/module/
reboot, `bpf`, `perf_event_open`, and `open_by_handle_at`. Denied calls return `EPERM` so a
program gets a clean, handleable error rather than being killed. The filter is inherited by
every `fork`/`exec` descendant, so the restriction cannot be shed by spawning a child.

## Network modes and clone filtering (Phase 6)

`--net none` (the default) is a seccomp rule on `socket()`'s first argument, the address
family: only `AF_UNIX` and `AF_NETLINK` may be created; everything else gets `EACCES`. We
chose an allowlist of families rather than a deny-list of `AF_INET`/`AF_INET6` so that a
family nobody thought about (`AF_VSOCK`, `AF_BLUETOOTH`, …) is denied by default. Denying at
socket *creation* means TCP, UDP and raw IP are all covered with one rule, and it does not
matter how the program spells the request — Python, bash's `/dev/tcp`, or C all end in the
same syscall. `--net all` simply omits the rule. There is no in-between mode: Landlock on
this kernel can only filter TCP by port and cannot see UDP at all, so a "some network" mode
would claim more than the kernel enforces.

`io_uring` is denied in every mode because its submission queue can perform socket, connect
and open operations without making the corresponding syscalls, which would slip past any
per-syscall seccomp rule.

Namespaces: `unshare`/`setns` were already denied, but `clone(CLONE_NEWUSER)` creates a
namespace too — and on this host it *succeeds* for an unprivileged process. We cannot deny
`clone()` outright (fork and threads use it), so the filter loads the flags argument, masks
the `CLONE_NEW*` bits, and denies only if any are set. `clone3()` passes its flags inside a
struct in user memory that seccomp cannot read, so we return `ENOSYS` for it; glibc and other
runtimes interpret that as an older kernel and fall back to `clone()`, where the flag filter
applies. The tests confirm fork, pthreads, Python threads/subprocess and git still work.

## Resource limits and the cgroup kill tier (Phase 7)

rlimits look like sandbox limits but are not: each process gets its own copy at fork, so
`--max-file-size 1M` means "no single process may grow a file past 1 MiB", not "the agent
may write 1 MiB". We set soft and hard equal so the target cannot raise them again, keep
core dumps off unconditionally (a crash dump of an agent can contain its API key), and
offer file-size and open-file bounds only on request. `RLIMIT_NPROC` is left alone because
it counts all of the user's processes on the machine, not the sandbox's.

The deadline already existed in the Phase 2 supervisor; Phase 7 does not add a timer. What
it adds is a better kill. A process group is a weak container: any descendant can call
`setsid()` and walk out of it, and the Phase 2 teardown could not reach it. cgroup v2 has
`cgroup.kill`, which kills every member of a cgroup atomically. So when the runner's own
cgroup is writable (delegated to the user, as the terminal scope is here), it creates an
owned child cgroup per run, the child joins it before doing anything else, and teardown
writes `cgroup.kill`. Landlock keeps `/sys/fs/cgroup` unwritable, so the target cannot move
itself back out. The test proves the difference both ways: the same setsid escapee
survives with the layer disabled and dies with it enabled.

We stop there. Real aggregate limits (`pids.max`, `memory.max`) need controllers switched
on in the parent cgroup, which belongs to the terminal and holds unrelated processes. The
runner reports aggregate limits as unavailable instead of pretending rlimits are enough.

## Policy files and why their location matters (Phase 8)

A policy file is control-plane data: whatever it says, the *next* run will enforce. If the
sandboxed agent could edit it, one run could widen the next run's cage. So the parser is
deliberately boring — `key = value` lines, one version, no quoting or expansion, every
oddity an error — and the interesting part is where the file lives.

String checks such as "does the path start with the workspace?" are easy to fool with
symlinks, `..`, or a second path to the same directory. Instead the runner insists on the
canonical path, opens the file without following links, and walks up from the directory it
actually opened, comparing device and inode numbers with each root the target will be
allowed to write. If the file or any directory above it is one of those roots, the run is
refused. The effective roots matter: the same file in `/tmp` is refused by default (the
target may write `/tmp`) and accepted once the policy turns default writes off. The runner
binary gets the same check, refused in policy mode, reported otherwise.

The tests then attack a protected policy and a copy of the runner from inside the sandbox
in every spelling we could think of and compare hashes, inode numbers and the directory
listing before and after — not just exit codes. Landlock does the actual blocking; the
location check guarantees the protected files are outside what Landlock grants.

What `--net none` does *not* do: it does not stop the sandboxed tree from talking to
same-UID services over Unix sockets. The Phase 6 probe showed the worst case — asking the
user systemd manager over D-Bus to start a process, which then runs with no AgentGuard
restrictions at all. That is recorded as a verified residual and belongs to Phase 9.

## Host IPC: what Phase 9 currently protects

Landlock's signal scope stops the target from signalling processes outside its domain,
including its supervisor. Its abstract-socket scope similarly protects outside abstract
Unix listeners. Children inside the domain can still signal and talk to one another.
seccomp also restricts `prlimit64` to pid zero, so a target can change its own limits but
cannot change an outside process's limits.

Memory access has two checks: seccomp rejects ptrace and process_vm syscalls, while
Landlock also checks the relationship between the caller's domain and the target's.
That Landlock check covers sensitive `/proc/PID/mem` and `/proc/PID/fd` access too.
Tests deliberately make a disposable sentinel traceable, prove that a baseline can
read/write it, then show that each relevant AgentGuard mechanism prevents the effect.
They do not mistake the host's Yama restrictions for AgentGuard protection.

SysV shared memory, semaphores and queues need their own rule: their numeric IDs are
not filesystem paths. The runner now denies their creation and access/control syscalls.
Tests allocate new objects, demonstrate outside-state changes without seccomp, then
check that protected runs leave the objects unchanged. Every object is removed by its
fixture owner. Applications requiring SysV IPC cannot use this seccomp policy.

The remaining boundary is still incomplete. Pathname Unix sockets can reach host
services, and datagram socketpairs can also send to a pathname socket. A test filter
blocks both, but breaks Python multiprocessing.Manager. It is not enabled in normal
runs. Instead status explicitly says **host IPC is not isolated**, even in strict mode.
Strict means required mechanisms apply; it is not a promise that every host interaction
is mediated. The session-D-Bus escape found in Phase 6 therefore still applies: it was
not re-run at the end of Phase 9 (it talks to a real host service), and nothing added
since mediates pathname sockets.

Likewise, a kept socket is deliberately delegated authority: its peer receives data
even though a non-kept socket would be closed. Default `/dev/shm` reads, `/dev/pts`
writes and AF_NETLINK are additional shared host surfaces demonstrated with fresh
fixtures. The host rejects the tested terminal-input ioctl even outside AgentGuard,
so we credit that to host policy. These limitations are listed in THREAT_MODEL §6.

Scheduling was another independent path: a process can lower a same-UID neighbor's nice
value or pin it to one CPU without ptrace or signals. The runner now restricts scheduling
setters to pid zero (the caller), and rejects group/user-wide priority selectors.
Disposable sentinel values demonstrate both the old effect and its prevention; ordinary
nice/taskset/chrt/ionice command launches remain usable. Programs that adjust another
thread by explicit TID are also denied, a limitation of this simple syscall filter.
Separately, a fresh POSIX message-queue fixture confirms that the current Landlock policy
denies opening it for send or receive. The outside queue still holds its original message.

## Running an agent under both layers (Phase 10)

`agentguard-agent -- claude` is a thin wrapper around `agentguard-run`. It makes the
repository the writable workspace, lets the agent's own install directory be read so it
can start, and grants write access to the agent's state files (`~/.claude`,
`~/.claude.json`). Everything else in your home directory stays invisible. Network
defaults to `all` for an API-backed agent — there is no destination filtering — and
`AGENTGUARD_NET=none` turns it off for offline work.

Claude Code then runs the V1 hooks itself, inside the sandbox. They still give early,
readable feedback ("blocked by policy pattern …"), keep snapshots and an audit log. But
since the repository is writable, a determined agent could edit the hook configuration with
a shell command; V1 is guidance for a cooperative agent, and V2 is what the kernel
enforces regardless. The Phase 10 tests check the everyday tools (git, make/gcc, Python,
Node) and that their children — a make recipe, a git hook, a Python grandchild — get the
same restrictions as the agent.

## How Phase 9 closed: weaken the claim, do not fake the mechanism

The Phase 9 gate asks that every host-IPC surface be classified Core, non-goal or degraded,
with fixture evidence — not that every surface be blocked. The project's scope rule says
that when a mechanism is missing, either add its minimum version or weaken the claim, and
prefer weakening. On this kernel there is no unprivileged mechanism that mediates pathname
Unix sockets without breaking ordinary tools, so the claim was weakened: AgentGuard V2 does
not isolate same-UID host services, every status report says so, and the threat model
scopes every guarantee to an adversary that does not use such services. If you need that
isolation, run the agent under a different user, in a VM, or in a container that has no
access to your session's runtime directory — and still use AgentGuard inside it.
