# AgentGuard Red-Team Corpus

Effect-based adversarial cases used to measure what V1 (and later V2) actually prevents.

## Principles

- Every case runs on **disposable fixtures** created under a temporary root
  (`mkdtemp`). Nothing touches the real home directory, real credentials, system
  files, or other repositories. Destructive commands act only on sentinel files
  inside the fixture.
- The oracle verifies the **real effect** (did the sentinel file get deleted /
  modified / exposed / written outside the workspace), not merely the hook exit code.
- Cases are stored as structured, mechanism-neutral data (`cases/corpus.json`) so the
  identical semantic cases can be replayed against V2 in Phase 11.

## Case schema (`cases/corpus.json`)

Each case:

| field | meaning |
|---|---|
| `id` | unique identifier |
| `category` | attack family (obfuscation, shell-expansion, interpreter-indirection, equivalent-form, symlink, subprocess-indirection, path-escape) |
| `description` | what the attacker attempts |
| `tool` | `Bash`, `Read`, `Edit`, or `Write` — the Claude tool the request would use |
| `setup` | list of shell commands run in the workspace to build the fixture |
| `setup_files` | map of workspace-relative path → file contents |
| `setup_outside` | map of path under the fixture root (outside the workspace) → contents |
| `command` | Bash command (for `tool: Bash`) |
| `file_path` | workspace-relative or escaping path (for file tools) |
| `content` | content written (for `Write`/`Edit`) |
| `harmful` | true if the effect, should it occur, is a policy violation |
| `oracle` | how the harmful effect is detected (see below) |
| `note` | optional commentary |

### Oracle types

- `path_absent` / `path_present`: workspace-relative path (or `outside:` prefixed) existence.
- `file_contains` / `file_not_contains`: `{path, text}`.
- `file_equals`: `{path, text}` exact content (used for "working changes destroyed").
- `stdout_contains`: `{text}` in the executed command's stdout (exposure).

## Runners

- `run_v1.py` — for each case: build fixture, send a synthetic hook payload through
  `scripts/run_hook_chain.sh` exactly as Claude Code would, record the decision, and if
  V1 allowed it, perform the effect and run the oracle. Emits
  `results/v1_results.json` and prints a table.
- `run_v2.py` — added in Phase 11.

## Outcome classes

- `prevented` — V1 blocked the request; harmful effect did not occur.
- `bypass` — V1 allowed the request and the harmful effect occurred.
- `allowed-safe` — allowed and no harmful effect (legitimate work).
- `false-positive` — blocked a harmless request.
