# Documentation

Start with the [project README](../README.md).

## V2 kernel sandbox (current reference)

| Document | Contents |
|---|---|
| [v2/ARCHITECTURE.md](v2/ARCHITECTURE.md) | Supervisor/child design, setup order, each enforcement layer, network modes, resource limits, policy format, V1 integration |
| [v2/THREAT_MODEL.md](v2/THREAT_MODEL.md) | Adversary, guarantees per mode, residual risks, non-goals, host-IPC surface inventory |
| [v2/TEST_PLAN.md](v2/TEST_PLAN.md) | Every suite, what its oracles check, CI tiers and skip rules |
| [v2/WALKTHROUGH.md](v2/WALKTHROUGH.md) | The mechanisms explained in plain language |
| [v2/V2_BUILD_REPORT.md](v2/V2_BUILD_REPORT.md) | Release-candidate summary: properties, comparison, tests, limitations |
| [../redteam/README.md](../redteam/README.md) | Red-team corpus format and outcome classes; results in [comparison.md](../redteam/results/comparison.md) |

## V1 workflow guardrails

| Document | Contents |
|---|---|
| [v1/THREAT_MODEL.md](v1/THREAT_MODEL.md) | Hook-layer assets, trust boundaries, controls and residual risks |

## Engineering history

Kept for traceability. Not needed to use or review the project.

| Document | Contents |
|---|---|
| [v2/PLAN.md](v2/PLAN.md) | Fixed phase roadmap and completion gates (phases 0–12) |
| [process/BUILD_LOG.md](process/BUILD_LOG.md) | Engineering log per phase: measurements, design decisions, bugs found, test counts, CI runs |
