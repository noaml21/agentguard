# AgentGuard Threat Model

## 1. Security Goal

AgentGuard reduces the risk of accidental or straightforward dangerous actions performed by an AI coding agent through supported Claude Code hooks. It evaluates selected Bash, Read, Edit, and Write requests, preserves eligible files before changes, checks supported source files after modification, and records local audit events.

The goal is defense in depth: block recognizable high-risk actions, constrain ordinary file-tool access to the workspace, preserve useful recovery evidence, and make agent activity more visible. AgentGuard is not a perfect isolation boundary. It is not a sandbox, container, kernel security mechanism, or complete parser for shell commands, Git invocations, secrets, or program semantics.

## 2. Assets

The assets in scope are:

- User source code and other files inside the active workspace.
- Git working-tree state, repository metadata, and history.
- Credentials and sensitive project files represented by the protected-path policy, including environment files, SSH material, private-key formats, and selected credential files.
- AgentGuard's hooks, shared library, configuration, dispatcher, Claude Code wiring, runtime state, snapshots, and audit log.
- The integrity and availability of the development workspace.

The policy protects named path categories rather than discovering all sensitive data. Files outside those categories may still be sensitive.

## 3. Trust Boundaries

The first boundary is between the AI agent and the tool request it generates. Tool names, commands, paths, session identifiers, and working directories are untrusted JSON input.

Claude Code is the integration boundary. It supplies hook payloads, invokes the configured commands, and interprets their exit codes and output. The project-owned `.claude/settings.json` sends matching PreToolUse and PostToolUse events through the dispatcher and invokes the SessionEnd summary directly.

The dispatcher and hooks form the policy-enforcement layer. They validate JSON, configuration syntax, paths, and persisted rate state before relying on them.

The workspace filesystem is both an asset and an input to decisions: canonical paths, symlinks, type, and existence affect policy and snapshots. The host, Bash, filesystem semantics, and required local binaries are trusted dependencies. AgentGuard does not defend against their compromise.

## 4. Threats and Mitigations

| Threat | Example | Mitigation | Residual Risk |
|---|---|---|---|
| Destructive shell command | `rm -rf`, `git reset --hard`, force push, or a download piped to a shell | The Bash PreToolUse firewall compares the command with repository-owned extended regular expressions and exits 2 on a match or policy error. | Regex matching is not complete shell analysis. Obfuscation, alternate programs, quoting tricks, or unsupported forms can bypass it. One allowed command can still have large impact. |
| Workspace path traversal | `../outside/secret` or an absolute path outside the workspace | File and snapshot hooks canonicalize the workspace and target, then require the target to remain under the workspace root. | Canonicalization is a point-in-time check. Filesystem topology can change afterward, creating a TOCTOU window. Other tool channels are not automatically covered. |
| Symlink escape | A workspace symlink resolves to a file outside the workspace | `realpath --canonicalize-missing` resolves the target before the containment check; tested symlink escapes are blocked. | A symlink or ancestor can be replaced between validation and tool execution. This is not an atomic filesystem capability boundary. |
| Access to sensitive files | Reading or editing `.env`, `.git/config`, SSH material, or private keys | The file policy blocks configured canonical workspace-relative paths for Read, Edit, and Write while allowing `.env.example` and `.gitignore`. | The list is selective, not DLP. Unrecognized sensitive files remain accessible, and an allowed Bash command can bypass the file hook. |
| Modification of AgentGuard controls or state | Editing hooks, config, `.agentguard/`, Claude settings, or the dispatcher | Protected-path rules block these targets through the Read/Edit/Write file-policy path. The dispatcher runs that policy before snapshots. | This is hook-level self-protection, not tamper-proofing. Bash-based writes, manual user action, or arbitrary OS-level access can modify or disable the controls. |
| Lost concurrent rate updates | Many Bash requests update one session simultaneously | The rate limiter holds an exclusive `flock` while reading, validating, incrementing, and replacing JSON state. | It limits quantity, not command impact. State is local and can be altered or removed by privileged actors. |
| Unsafe modification without a recovery copy | An Edit overwrites an existing source file | Before Edit/Write, the snapshot hook copies an existing regular file into path-hashed version storage and rotates retained versions. | Snapshots are not transactional rollback, exclude nonexistent targets and changes outside this chain, and never restore files automatically. |
| Syntactically broken generated code | An Edit leaves invalid Bash, Python, or C | PostToolUse runs `bash -n`, an artifact-free Python compilation check, or `gcc -fsyntax-only`, and reports failure with exit 2 and diagnostics. | The write has already happened. The check detects but cannot undo it. Unsupported file types are skipped, and syntax validity does not imply semantic correctness or security. |
| Malformed hook or configuration input | Invalid JSON, regex, AgentGuard assignment, or rate state | Security-critical hooks validate one JSON value and fail closed on required input or policy errors. Configuration and persisted rate state are validated before use. | Validation covers expected formats, not arbitrary semantics. SessionEnd is non-blocking, and PostToolUse cannot prevent a completed write. |
| Problematic commit message | A direct commit uses an unknown type or invalid scope | The hook tokenizes direct `git commit` commands with Python `shlex` and validates supported static messages against configured prefixes and formatting rules. | It does not parse every shell or Git invocation. Commands without a supported static message are skipped. |
| Loss of visibility | A blocked or allowed action leaves no understandable record | Hooks construct JSON objects with `jq` and append JSONL audit events containing timestamp, session, event, hook, decision, and reason. SessionEnd summarizes events for the selected session. | Audit writes are best-effort, local, and not tamper-evident. OS-level attackers can delete or alter them, and concurrent or storage failures can reduce visibility. |

## 5. Ordering and Composition

Claude Code may run separate matching hook handlers in parallel, so AgentGuard wires one handler to `scripts/run_hook_chain.sh` and performs security-sensitive steps sequentially inside that process.

For Bash PreToolUse requests, the chain is:

1. Command firewall
2. Rate limiter
3. Commit policy

This prevents a recognized dangerous command from consuming rate quota before it is denied. Commit-message validation occurs only after the general Bash protections pass.

For Edit and Write PreToolUse requests, the chain is:

1. File policy
2. Pre-change snapshot

This ordering prevents a protected target such as `.env` from being copied into snapshot storage before access is denied. Read requests run only the file policy. Edit and Write PostToolUse requests run the syntax checker, after the tool has already changed the file.

The dispatcher stops when a hook returns 2 and preserves its diagnostic. It also converts unexpected nonzero hook failures into exit 2. This sequencing applies only within one dispatched hook chain; it does not globally serialize unrelated Claude operations or independent processes.

## 6. Fail-Closed vs Best-Effort Behavior

Security-critical PreToolUse paths fail closed. Malformed dispatcher or hook JSON blocks the request. Missing, unreadable, or invalid command and file policies block evaluation. Invalid required rate configuration, corrupted rate state, or failure to acquire/update its lock and state blocks a Bash request. For an existing file, failures while validating snapshot configuration or creating, recording, copying, or rotating its snapshot block the proposed Edit or Write.

Audit logging is best-effort after a hook establishes its decision. A write failure alone does not change an allowance or denial; doing so would make workspace availability depend on secondary observability storage.

SessionEnd reporting is also best-effort and always non-blocking. Missing activity produces a structured no-activity message, while malformed audit data produces an unavailable-summary message rather than interfering with session termination.

## 7. Explicit Non-Goals

AgentGuard does not provide:

- Arbitrary shell sandboxing or complete shell grammar analysis.
- Syscall filtering, mandatory access control, or process isolation.
- Container or virtual-machine isolation.
- Malware detection or behavioral endpoint protection.
- Complete secrets discovery or data-loss prevention.
- Protection against root or administrator compromise.
- Protection against a user manually disabling or rewriting AgentGuard.
- A guarantee of semantic correctness, safety, or security for generated code.

## 8. Validation

The repository-owned Bash suite contains 40 deterministic tests using temporary workspaces, state, synthetic hook payloads, and isolated configuration copies. It covers representative dangerous commands; malformed JSON; protected, traversing, absolute, and symlinked paths; control-plane protection; rate warnings and limits; corrupted state and configuration; and 20 simultaneous rate-limiter calls whose final count must be 20.

Snapshot tests verify nonexistent-target behavior, exact byte preservation, distinct same-basename paths, rotation, and workspace escapes. Syntax tests cover valid and invalid Bash, Python, and C without compiler artifacts, plus unsupported types. Commit tests cover supported messages and representative invalid or unparsed forms. Dispatcher tests verify firewall-before-rate-limit and file-policy-before-snapshot ordering. SessionEnd tests verify per-session counts, valid structured output, malformed audit handling, and no-activity output.

Claude Code wiring is implemented against the documented hook interface and validated with synthetic hook payloads and dispatcher integration tests. The repository has not yet been validated through an authenticated live Claude Code session.

## 9. Future Hardening

Potential hardening directions include structured command parsing or an allow-list mode, integration with OS or container isolation, tamper-evident or remote audit storage, more atomic filesystem enforcement, and adapters for additional coding agents. These would complement rather than change the current risk-reduction scope.
