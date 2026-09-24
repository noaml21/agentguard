# Build State (resume pointer)

- **Branch**: `v2/kernel-sandbox` (never merge to `main`).
- **Current phase/unit**: Phase 2, unit 2.1 (C runner: CLI, execvp, root refusal).
- **Latest verified commit**: see `git log -1` (Phase 1 corpus commit).
- **Complete**: Phase 0 (capability audit); Phase 1 (V1 red-team baseline:
  11 bypass / 7 prevented / 2 allowed-safe, `redteam/results/v1_results.json`).
- **Partial**: none.
- **Next action**: create `sandbox/` C project: `agentguard-run` argv parsing with a
  `--` separator, execvp-style exec (no shell), refuse EUID 0, propagate exit status
  (128+signo on signal death). Add `sandbox/Makefile` with `-Wall -Wextra -Werror` and
  an ASan/UBSan target, and `sandbox/tests/` harness. Build up lifecycle/FD/TTY in units
  2.2-2.4 per PLAN.
- **Running checks**: `./tests/run_tests.sh` (40 pass); `python3 redteam/run_v1.py`
  (bypass=11); `bash scripts/capability_audit.sh`.
- **Known constraints/blockers**: live V1 hooks limit Bash to 50 requests per Claude
  session; batch Bash work. Do not modify hooks. V2 code lives outside control-plane paths.
