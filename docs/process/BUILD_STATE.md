# Build State (resume pointer)

- **Branch**: `v2/kernel-sandbox` (never merge to `main`).
- **Current phase/unit**: Phase 1, unit 1.1 (V1 red-team corpus).
- **Latest verified commit**: see `git log -1`; Phase 0 docs commit.
- **Complete**: Phase 0 (capability audit recorded in `docs/v2/ARCHITECTURE.md` and BUILD_LOG).
- **Partial**: none.
- **Next action**: create `redteam/cases/` structured corpus and `redteam/run_v1.py`
  driving `scripts/run_hook_chain.sh` with synthetic payloads in disposable fixtures,
  then execute allowed commands inside the fixture and check effects.
- **Running checks**: none.
- **Known constraints/blockers**: live V1 hooks limit Bash to 50 requests per Claude
  session; batch Bash work and resume in a new session when exhausted. Do not modify hooks.
