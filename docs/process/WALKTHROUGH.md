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
