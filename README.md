# AgentGuard

AgentGuard is a runtime guardrail layer that reduces risk from AI coding agents performing local shell and file operations.

AI coding agents can execute commands and modify files with the user's local privileges, so a plausible-looking request can damage a workspace, expose sensitive files, or leave code in a broken state. AgentGuard adds policy checks, pre-change recovery copies, bounded command counting, and audit visibility around selected tool operations. Claude Code is the first integration; AgentGuard is a guardrail layer, not a sandbox or isolation boundary.

## Why AgentGuard?

The difficult part is not any single check, but composing checks safely. A generated command may be destructive, a path may escape through `..` or a symlink, parallel hook handlers may violate required ordering, and concurrent state updates may lose counts. Some controls also operate after the fact: PostToolUse syntax validation can report a bad write, but cannot prevent or undo the write that already occurred.

AgentGuard demonstrates defensive handling of these boundaries while keeping its guarantees explicit and testable.

## Architecture

```text
Claude Code
    |
    v
.claude/settings.json
    |
    +-- PreToolUse / PostToolUse
    |       |
    |       v
    |   scripts/run_hook_chain.sh
    |       |
    |       +-- Bash:       firewall -> rate limiter -> commit policy
    |       +-- Read:       file policy
    |       +-- Edit/Write: file policy -> pre-change snapshot
    |       +-- Post Edit/Write: syntax checker
    |
    +-- SessionEnd: session_end_summary.sh (direct)
```

The dispatcher runs each selected chain sequentially. Separate matching Claude hook handlers may otherwise run independently, but AgentGuard needs invariants such as firewall-before-rate-limit and file-policy-before-snapshot. This sequencing applies within one dispatched request; it does not globally serialize unrelated agent operations.

## Controls

| Control | Purpose |
|---|---|
| Command firewall | Blocks representative destructive Bash command strings using repository-owned extended regular expressions. Policy errors fail closed. |
| File/workspace policy | Canonicalizes paths, enforces workspace containment, detects tested traversal and symlink escapes, protects named sensitive paths, and blocks Read/Edit/Write access to AgentGuard's control-plane paths. |
| Rate limiter | Counts nonempty Bash requests per session. An exclusive `flock` protects validated read-modify-write state, which is replaced through a temporary file. |
| Pre-change snapshots | Copies existing regular-file bytes before Edit/Write into path-hashed storage. Configuration bounds retained versions and separates same-basename paths. |
| Commit policy | Uses Python `shlex` without command execution to validate supported static `git commit` messages against configured prefixes and formatting rules. |
| Syntax checker | After Edit/Write, validates Bash with `bash -n`, Python with an artifact-free compilation check, and C with `gcc -fsyntax-only`. Unsupported types are skipped. |
| Audit and SessionEnd summary | Appends structured JSONL events with decision context and emits a structured summary for the selected session. Both are local observability mechanisms. |

Security-critical PreToolUse parsing, required policy, rate-state, and existing-file snapshot failures block with exit code 2. Audit writes and SessionEnd reporting are intentionally best-effort so an observability failure alone does not change an already established policy decision.

## Security Properties Tested

The repository contains **40 deterministic tests**. They use synthetic hook payloads, temporary workspaces, isolated `AGENTGUARD_STATE_DIR` directories, and temporary configuration copies; dangerous command strings are evaluated but never executed.

Representative tested properties include:

- Destructive command patterns are blocked, including recursive deletion and destructive Git operations.
- Workspace traversal, absolute outside paths, and symlink escapes are blocked.
- `.env`, Git internals, AgentGuard control-plane files, runtime state, and Claude hook wiring are protected through file-tool policy.
- A blocked dangerous command stops before rate-limit state is created.
- A blocked protected Edit stops before snapshot creation.
- Twenty simultaneous rate-limiter calls produce a final count of exactly 20.
- Snapshots preserve exact pre-change bytes, avoid same-name collisions, and rotate to the configured bound.
- Valid and invalid Bash, Python, and C are distinguished without Python cache or C build artifacts.
- SessionEnd output counts only the selected session and remains non-blocking for malformed or absent audit data.

Run the suite from the repository root:

```bash
./tests/run_tests.sh
```

Expected current summary:

```text
40 passed, 0 failed
```

## Example

This simplified example uses the production diagnostic prefix; it is not a live Claude Code transcript:

```text
Bash request: rm -rf /tmp/project
Result: exit 2
stderr: AgentGuard firewall: BLOCKED by policy pattern: <matched rule>

Bash request: git status
Result: exit 0
```

## Repository Layout

```text
.claude/settings.json          Claude Code project hook wiring
agentguard/
  hooks/                       Runtime policy and lifecycle hooks
  lib/                         Shared Bash helpers
  config/                      Repository-owned policies and limits
scripts/run_hook_chain.sh      Sequential PreToolUse/PostToolUse dispatcher
tests/run_tests.sh             Independent deterministic test suite
THREAT_MODEL.md                Detailed assets, boundaries, and residual risks
```

## Requirements

AgentGuard targets Linux and Bash. The implementation and tests require:

- Bash
- `jq`
- `flock`
- GNU `realpath`
- `sha256sum`
- Python 3
- GCC
- Git

Claude Code is required only to use the Claude integration. It is not required to run the repository test suite.

## Running the Tests

From the repository root:

```bash
./tests/run_tests.sh
```

The harness exits 0 only when every test passes. It creates one temporary root with per-test workspaces and state, uses isolated project copies for configuration variants, and removes temporary data through a trap.

## Claude Code Integration

Project hook wiring is present in `.claude/settings.json` and uses `${CLAUDE_PROJECT_DIR}` for portable command paths. PreToolUse and PostToolUse requests are sent through the sequential dispatcher, while SessionEnd invokes the summary hook directly.

The wiring targets Claude Code's documented hook interface and is covered by synthetic payload and dispatcher integration tests. A live authenticated Claude Code session has not yet been used as part of validation.

## Security Model and Limitations

AgentGuard reduces risk; it does not contain an agent. The command firewall is regex-based and bypassable through obfuscation or unsupported forms. Canonical path validation has a time-of-check/time-of-use window, and an otherwise allowed Bash command can bypass Read/Edit/Write file policy. Snapshots are recovery copies rather than transactional rollback. PostToolUse syntax checks detect errors after modification and do not establish semantic correctness or security. Audit logs are local, best-effort, and not tamper-evident against an OS-level attacker.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the complete trust boundaries, mitigations, non-goals, and residual risks.

## Design Highlights

- Deterministic, fail-closed ordering for security-critical hook chains.
- Canonical path containment with explicit control-plane protection.
- `flock`-protected state updates and same-directory temporary replacement.
- Path-hashed, bounded pre-change snapshots.
- Structured JSONL audit events with best-effort session reporting.
- Independent integration tests with no Claude Code authentication dependency.
