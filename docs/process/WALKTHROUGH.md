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
- **Mark fds close-on-exec rather than close them**: setup still needs a few descriptors,
  and `execve` closes all CLOEXEC descriptors atomically at the moment the target starts.

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

What `--net none` does *not* do: it does not stop the sandboxed tree from talking to
same-UID services over Unix sockets. The Phase 6 probe showed the worst case — asking the
user systemd manager over D-Bus to start a process, which then runs with no AgentGuard
restrictions at all. That is recorded as a verified residual and belongs to Phase 9.
