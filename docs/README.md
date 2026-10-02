# AgentGuard documentation

Start with the [project README](../README.md). Then, by question:

| Question | Document |
|---|---|
| What does V2 enforce, and how is it built? | [v2/ARCHITECTURE.md](v2/ARCHITECTURE.md) |
| What is guaranteed, in which mode, against whom — and what is not? | [v2/THREAT_MODEL.md](v2/THREAT_MODEL.md) |
| Which tests prove each claim, and what runs in CI? | [v2/TEST_PLAN.md](v2/TEST_PLAN.md) |
| How do the mechanisms work, in plain language? | [process/WALKTHROUGH.md](process/WALKTHROUGH.md) |
| What is the release-candidate status and evidence summary? | [v2/V2_BUILD_REPORT.md](v2/V2_BUILD_REPORT.md) |
| How does V1 compare with V2 on the same attacks? | [../redteam/results/comparison.md](../redteam/results/comparison.md), [../redteam/README.md](../redteam/README.md) |
| What are the V1 hook layer's boundaries? | [../THREAT_MODEL.md](../THREAT_MODEL.md) |

Engineering process records (kept for traceability, not required reading):

- [v2/PLAN.md](v2/PLAN.md) — the fixed phase roadmap and completion gates.
- [process/BUILD_LOG.md](process/BUILD_LOG.md) — append-only evidence log, per session.
- [process/BUILD_STATE.md](process/BUILD_STATE.md) — current resume pointer.
