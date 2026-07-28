# Repository document and artifact lifecycle

This policy keeps the public source tree understandable and prevents experiments,
generated outputs, and operational transcripts from becoming accidental product
contracts.

## Authority rules

- `roadmap/roadmap.yaml` is the only delivery-order and compact-status authority.
- A matching `roadmap/state/GNN.json` is authoritative detail only while that
  canonical goal is active or delivered.
- Goal files define acceptance; they do not self-report completion.
- Issue maps, legacy coverage, migration notes, and historical plans are
  traceability aids. They cannot advance roadmap state.
- Repository validation proves only the checked source revision. It cannot
  establish a live deployment outcome.

## Lifecycle by material type

| Material | Required treatment |
| --- | --- |
| Stable product contract | Version, owner, compatibility policy, tests, and migration notes. |
| Reference implementation | Label `reference`, state the demonstrated contract, and list explicit non-claims. |
| Experiment or spike | Label `experimental`, name an owner and decision/expiry condition, and keep it off supported paths. |
| Drill tooling | Keep generic reusable machinery; keep provider inputs and live receipts outside the public repository. |
| Generated document or code | Record source, generator, deterministic regeneration command, and review the generated diff. |
| Requirement | Give it a stable ID and canonical roadmap owner; do not create a parallel status ledger. |
| Evidence | Commit only source-safe schemas, synthetic fixtures, or small public release attestations. Never commit raw live transcripts, credentials, private endpoints, tenant data, or screenshots containing private state. |
| Operational artifact | Logs, PID files, temporary patches, local profiles, caches, and command output stay untracked and expire outside Git. |
| Historical document | Label `historical` or `compatibility`; link to the current authority and do not update it as if active. |

## Promotion

An experimental or reference surface becomes supported only when its public
contract, owner, positive and negative tests, documentation, compatibility
policy, and applicable release checks are accepted together. A live deployment
elsewhere cannot silently promote public source.

## Retirement

Before removal:

1. identify code, CI, documentation, and downstream consumers;
2. preserve stable requirement and release provenance;
3. provide a replacement or explicit end-of-life notice where compatibility was
   promised;
4. remove generated outputs with their obsolete source, not independently;
5. verify links, roadmap ownership, tests, and source safety.

If consumer impact cannot be determined quickly, retain the material with an
explicit maturity label and create a bounded follow-up instead of guessing.

## Availability terminology

Names such as `three-node` and one-server-loss scenarios describe reference test
profiles. Portable HA requirements must be expressed through a declared failure
model, failure domains, quorum, replication, RPO/RTO, continuity thresholds, and
measured SLOs. Until that topology-neutral contract is implemented, reference
profiles must not be presented as universal product guarantees.
