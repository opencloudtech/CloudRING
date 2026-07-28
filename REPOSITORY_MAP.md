# CloudRING repository map

This map is the public front door to the source tree. A path has no implied
maturity merely because it is present; use the label in its nearest README or
the [public current state](roadmap/CURRENT_STATE.md).

## Maturity vocabulary

| Label | Meaning |
| --- | --- |
| `supported` | Maintained for the explicitly documented repository or release use case. |
| `reference` | Runnable example or contract implementation used to demonstrate and test an interface; not a production deployment promise. |
| `experimental` | May change or be removed; unsuitable for production dependence. |
| `planned` | Described in the canonical roadmap but not implemented. |
| `blocked` | A stated acceptance condition is missing or contradicted by an open defect. |
| `historical` | Retained only for provenance or compatibility; never a status authority. |
| `generated` | Reproducible output whose source and regeneration command must be documented. |

## Source layout

| Path | Purpose | Current maturity |
| --- | --- | --- |
| `cmd/` | Public CLIs for contract validation, roadmap verification, source safety, recovery, and reference operations. | Mixed `supported` repository tooling and `reference` operations; each command's help/README defines its scope. |
| `pkg/` | Reusable Go packages for OCS, identity/IAM primitives, provider adapters, resilience, secure execution, and transactional state. | Implemented slices; not a complete provider runtime. |
| `internal/` | Implementation details for public commands and validators. | Internal API; no compatibility promise. |
| `sdk/ocsv3/` | OCS Go SDK and authoring surfaces. | Early `reference`; OCS 1.0 is planned. |
| `contracts/` | Versioned schemas, fixtures, and validation contracts. | Contract-specific; a schema alone is not runtime readiness. |
| `modules/` | Public OCS module-package definitions and early module slices. | Mostly `reference` or `experimental`. |
| `reference/` | Synthetic end-to-end examples with no real provider or tenant data. | `reference`. |
| `examples/` | Source-safe positive and negative examples. | `reference`; never live evidence. |
| `deploy/` | Provider-neutral Kubernetes deployment bases and profiles. | Mixed `reference`, `experimental`, and `blocked`; not a complete installer. |
| `docs/` | Developer, operator, architecture, security, and contract documentation. | Normative only where a document explicitly says so. |
| `specifications/` | Stable requirement/specification inputs retained for traceability. | Versioned product input; delivery status lives only in the roadmap. |
| `roadmap/` | Canonical delivery graph, goal contracts, public current-state orientation, and evidence schemas. | [`roadmap.yaml`](roadmap/roadmap.yaml) is the sole status authority. |
| `.github/` | Contribution, ownership, CI, security, and supply-chain policy. | `supported` repository governance. |

## Source-of-truth table

| Concern | Authority |
| --- | --- |
| Delivery order and compact status | `roadmap/roadmap.yaml` |
| Detailed active-goal state | Matching `roadmap/state/GNN.json`, only after a goal starts |
| Goal acceptance contract | `roadmap/goals/GNN-*.md` |
| Public capability orientation | `roadmap/CURRENT_STATE.md` |
| Target architecture | `roadmap/TARGET_ARCHITECTURE.md` |
| Contribution and decision rights | `CONTRIBUTING.md` and `GOVERNANCE.md` |
| Security reporting | `SECURITY.md` |
| Path ownership | `.github/CODEOWNERS` |
| Artifact and document lifecycle | `docs/repository-lifecycle.md` |

Legacy Goal 01, coverage bridges, issue maps, and historical plans preserve
traceability. They do not compete with `roadmap.yaml` and cannot make a delivery
claim.

## Ownership and changes

`CODEOWNERS` identifies the required maintainer for sensitive paths. Changes
should be small, provider-neutral, source-safe, tested, and complete enough to
deliver their claimed behavior. Concrete infrastructure or private data must be
kept outside this repository; see [public boundary](docs/public-boundary.md).
