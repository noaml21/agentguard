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

Filled in as phases complete. Nothing below is claimed yet.

| Property | strict (unprivileged baseline) | degraded (explicit) | enhanced (namespaces) |
|---|---|---|---|
| Writes outside workspace denied | planned (Phase 4) | only if Landlock applied | UNAVAILABLE on dev host |
| Target never runs before enforcement | planned (Phase 3) | same | — |
| No privilege gain via setuid | planned (no_new_privs) | same | — |
| Network | per network mode (Phase 6) | — | UNAVAILABLE on dev host |
| Same-UID signals to outside processes | planned (Landlock scope, ABI ≥ 6) | — | — |
| Same-UID ptrace | planned (seccomp deny + Yama scope 1 ASSUMED) | — | — |

## 5. Non-goals

- Kernel compromise or kernel bugs.
- Damage inside the writable workspace that the policy intentionally permits.
- Vulnerabilities in binaries the policy allows the agent to run.
- Destination/host-level network filtering (Landlock is port-only; no proxy in Core).
- Guarantees that the active mode reports as unavailable or degraded.
- Running as root.
