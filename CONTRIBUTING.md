# Contributing

Read [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT-MODEL.md) and [detections](docs/DETECTIONS.md) first. Work from a new local environment; bootstrap your own operator and use replay. Install requirements-dev.txt and run pytest, Ruff and native JS syntax checks. Browser QA must use generated private credentials and actual parser-produced replay data.

Changes must preserve ingress-assigned provenance, bounded queues/state, metadata privacy, explainable rule units, manual response and kernel readback. A new rule needs stable ID/version, positive and benign/boundary tests, scope, unit/window, evidence requirement, benign causes, eligible origins/response, and a reusable fixture. ATT&CK mappings require rationale and primary references; no decorative confirmed-compromise claims.

Never submit credentials, real/private PCAPs, SQLite DBs, logs, .workbench, virtual environments, caches or generated packages. Attach permissioned sanitized screenshots with the origin/run visible. Label a test double explicitly; it is not live enforcement proof. Review contributor rights before adding/license-changing code or assets.

Keep PRs narrow and reviewable: concrete behavior, why it matters, actual checks, remaining platform limits. Privileged tests are explicit owner-run acceptance steps, never an implicit hosted PR workflow.

Contributions must be yours to submit under the repository [Apache-2.0 license](LICENSE). Preserve third-party notices and identify externally sourced material. No contributor assignment or additional contributor agreement is implied.
