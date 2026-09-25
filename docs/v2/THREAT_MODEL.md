# AgentGuard V2 Threat Model

Claim tags: **IMPLEMENTED** (code exists), **VERIFIED** (test evidence on a named host),
**ASSUMED** (relied on, not tested), **UNAVAILABLE** (host/kernel lacks it),
**DEGRADED** (weaker in the named mode). Every claim is scoped to a mode.

## 1. Why V1 is insufficient

V1 (see `/THREAT_MODEL.md`) inspects tool-request *text*: a regex firewall for Bash
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
| No privilege gain via setuid | VERIFIED (no_new_privs applied) | same | — |
| Filesystem reads/writes outside the policy denied | VERIFIED (Landlock, Phase 4 matrix) | only if Landlock applied | UNAVAILABLE on dev host |
| ptrace / process_vm_* / namespace creation+join / mount (incl. new mount API) / module / kexec / bpf / perf / io_uring denied | VERIFIED (seccomp, Phases 5–6) | only if seccomp applied | — |
| `--net none`: no IP (v4/v6 TCP, UDP, raw) or other non-local socket can be created | VERIFIED (socket-family allowlist; effect tests with loopback listeners) | NOT enforced if seccomp missing — reported in status + warning | UNAVAILABLE on dev host |
| `--net all`: host networking; no destination filtering | by design | same | — |
| Same-UID signals to outside processes | planned (Landlock scope, Phase 9); not applied | — | — |
| Same-UID ptrace | VERIFIED seccomp deny; Yama scope 1 ASSUMED as backstop | — | — |

### 4.1 Known residuals (current)

- **Same-UID host IPC escape — VERIFIED, all modes.** AF_UNIX connects to same-UID host
  services are not mediated at Landlock ABI 8 (pathname-unix needs ABI 9; abstract-unix
  scoping not applied yet). On the dev host, a process inside `--net none` asked the user
  systemd manager (`systemd-run --user`, over `/run/user/1000/bus`) to start a process; that
  process had `Seccomp: 0`, `NoNewPrivs: 0`, and could create `AF_INET` sockets — it is
  outside every V2 layer. Same-host daemons can also relay traffic (e.g. DNS via
  systemd-resolved). Until Phase 9 closes or explicitly scopes this, V2 guarantees hold only
  against an adversary that does not use host IPC services.
- **clone3**: flags are unfilterable (struct in user memory); mitigated by returning
  `ENOSYS` so callers fall back to the flag-filtered `clone()`. A program that *requires*
  clone3 (no fallback) fails; none observed (glibc, python, git, gcc tested).
- **`fsopen`/`fsconfig`/`fsmount`, `CLONE_NEWNET`, `syslog`**: already `EPERM` for an
  unprivileged process on the dev host (no caps; `dmesg_restrict=1`), so their seccomp
  rules are belt-and-suspenders and the tests do not independently prove them there.
- **No destination filtering** in any mode; `--net all` is full host networking.

## 5. Non-goals

- Kernel compromise or kernel bugs.
- Damage inside the writable workspace that the policy intentionally permits.
- Vulnerabilities in binaries the policy allows the agent to run.
- Destination/host-level network filtering (Landlock is port-only; no proxy in Core).
- Network-namespace isolation (namespace tier unavailable on the dev host).
- Guarantees that the active mode reports as unavailable or degraded.
- Running as root.
