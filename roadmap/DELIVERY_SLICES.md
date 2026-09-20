# Intermediate releases and full qualification

This execution sequence produces a useful developer VM before full production
qualification. C01–C28 are delivery slices of the existing G requirements. They
do not create a second requirement registry, runtime scheduler or evidence
protocol. The original goal files, `COVERAGE.md`, `ISSUE_MAP.md`,
`LEGACY_WORK_MAP.md` and the execution, measurement and evidence contracts remain
normative. Every criterion under a mapped goal, including its inherited legacy
requirements and issues, is carried to the full-qualification owner below.

An accepted slice must have its actual working journey, protected source,
immutable signed prerelease, applicable clean-room and live verification,
regression and cleanup evidence. A partial slice records its precise coverage
and remaining blockers in the owning `state/GNN.json`; it never marks a whole G
goal delivered. No fictional deployment, fixture, namespace or agent role can
replace required independent infrastructure or a real human participant.

`in_progress` means work has started and requires a valid state record. It does
not assert readiness or completed predecessors. `delivered` still requires every
qualification dependency and the original full evidence contract. C dependencies
below control implementation entry; read-only preparation can happen earlier.
External authorization or capacity blocks its affected live result while
independent authorized work continues.

## Slice sequence

| Slice | Entry | Accepted working result | Original coverage and full-qualification boundary |
| --- | --- | --- | --- |
| C01 | None | Reproducible public delivery baseline; useful delivery fixes accepted; every current-family WIP root classified and preserved; invalid candidate rejected; fixed numeric measurement profiles. | Partial G00 / CR-G00-DELIVERY. Current endpoint, GitOps revision and separately verified or unknown host-binary provenance are recorded. Full downstream/live G00 qualification follows in C08. Proposed downstream requirements are not automatically ratified. |
| C02 | C01 accepted | Public isolated developer create, repeat, restart, positive/negative smoke, destroy with zero owned residue and recreate; same profile beside reference installation. | Full G01 / CR-G01-DEV-INSTALL, including clean-room tutorial and human/installation profile. Production shortcuts must be rejected. G01 does not wait for full G00. |
| C03 | C02 | Public durable project/operation API, CLI and read-only UI; transactions, outbox, crash, retry, concurrency, migration and restore. | Partial G03 / CR-G03-KERNEL. Full directory, production failover and scale qualification in C09. |
| C04 | C03 | Two developer tenants invite/login/use own project/logout; token/session revocation and direct API/browser isolation negatives. | Partial G04 / CR-G04-IDENTITY and G05 / CR-G05-IAM. Full production identity, recovery and workload identity in C09. |
| C05 | C04; applicable C06 barriers for reference-site mutations | Real developer VM through public Go/OCS; login, project, create, bounded access, write/read digest, retry/restart, one VM, delete and cleanup; one real user performs a useful task. | Partial G07–G09 and G15 / CR-G15-COMPUTE. Quota/reservation and explicit zero-priced-metered or non-billable policy required now. Pilot dependencies are owned and bounded; Network/Volume/Image products and full Compute remain incomplete. |
| C06 | C01 | Existing reference installation restored from independent off-cell copies; etcd, PostgreSQL, secrets and applicable volumes have actual data, ownership, RPO/RTO, rollback and cleanup proof; backup freshness and telemetry observed. | Preparatory G02, G17, G18, G22, G23; legacy Tasks 21–22. This is platform recovery, not acceptance of tenant backup/object products. |
| C07 | C06 for live changes | Exact GitOps origin/API routing, allocation, direct IPv4/IPv6 TLS and declared failure/rollback verified using actual provider bindings. | Preparatory G02, G12 and G23; Task 23. CDN fallback does not prove origin; tenant Network product waits for C15. |
| C08 | C02, C06, C07 | Independent public HA empty-provider install, upgrade, failed canary, rollback, rotation, restore and disposable destroy; public signed serving artifacts with source provenance. | Full G00 / CR-G00-DELIVERY and G02 / CR-G02-HA-INSTALL. All original downstream, protected delivery, canary, exact pin and live-readback criteria retained. |
| C09 | C03, C04, C05, C08 | Production kernel, identity and IAM: directory sync, durable migrations/failover, registration/recovery, external identity, workload grants and complete deny/revoke/audit journeys. | Full G03 / CR-G03-KERNEL, G04 / CR-G04-IDENTITY, G05 / CR-G05-IAM. Developer VM regression remains green. |
| C10 | C09 | Real inventory, explicit adoption/relinquish, drift, durable executor, ambiguous-side-effect reconciliation and two independent adapter implementations. | Full G06 / CR-G06-PROVIDER-OPS. |
| C11 | C05, C10 | Independent original product from public SDK; OCS RC local/remote/API-only, registry/admission, commercial eligibility, optional isolated UI, upgrade/rollback/remove and empty catalog. | Full G07 / CR-G07-OCS-RC and G08 / CR-G08-REGISTRY. Human two-hour test requires a real independent mid-level developer; OCS is not frozen 1.0. |
| C12 | C11 | Complete real order/subscription/entitlement lifecycle, quota/capacity, compensation, crash/retry/cancel and restore through both connector paths. | Full G09 / CR-G09-LIFECYCLE. |
| C13 | C12 | Real test usage to exact balanced ledger, invoice, correction, budget and publisher share with replay/restore/HA and eligibility denial. | Full G10 / CR-G10-BILLING. Uses isolated non-financial data; actual customer charging needs separate authority. |
| C14 | C13 | Equivalent complete API/CLI/portal/agent actions, policy, identity, audit, resumability, accessible UI and authoritative backend comparison. | Full G11 / CR-G11-EXPERIENCE. |
| C15 | C14, C07 | Standalone OCS Network lifecycle, dual-stack connectivity, tenant denial, quota/usage, actual failure and cleanup. | Full G12 / CR-G12-NETWORK. |
| C16 | C14, C08 | Standalone OCS Volume lifecycle, real CSI/snapshot/restore, encryption, node-loss digest and accounting. | Full G13 / CR-G13-VOLUME. Independent of C15; production rejects replication-one or unknown topology. |
| C17 | C16 | Standalone OCS Image/Artifact lifecycle, immutable provenance, VM/OCI round trip, resumable import, scan/quarantine, boot harness, restore and safe GC. | Full G14 / CR-G14-ARTIFACT. Boot harness does not require completed C18. |
| C18 | C15, C16, C17 | Complete Compute through ordinary Network/Volume/Image entitlements; full use, access, billing, failure and recovery; existing pilot user migrates or exports data safely. | Full G15 / CR-G15-COMPUTE. Supported cold recovery is measured; live migration is claimed only with its actual prerequisites and proof. |
| C19 | C18 | Real tenant Kubernetes, workload/data, short-lived access, scale, signed upgrade, failure, isolated restore and full cleanup. | Full G16 / CR-G16-KUBERNETES. |
| C20 | C14, C16, C19 | Real local/reference and remote S3 lifecycle, objects/digests, credentials, retention, metering, failure and isolated restore. | Full G17 / CR-G17-OBJECT. Replace placeholder catalog path; unsupported durability cannot pass full product acceptance. |
| C21 | C19, C20 | Customer self-service backup and verified off-cell restore of every claimed data class, ownership, retention, retries, RPO/RTO, cost and cleanup. | Full G18 / CR-G18-BACKUP. |
| C22 | C19, C21 | Supported SSH/Kubernetes/console access request, approval, grant, use, expiry/revoke and recovery without reviving grants. | Full G19 / CR-G19-ACCESS. |
| C23 | C22 | Durable support case, consent, bounded redacted bundle, controlled access, routing outage, escalation, resolve and restore. | Full G20 / CR-G20-SUPPORT. |
| C24 | C23 | Real authorized remote/API-only system with complete lifecycle/usage and two independent replaceable adapters; independent developer uses public core only. | Full G21 / CR-G21-EXTERNAL. Unimplemented external templates remain templates. |
| C25 | All C01–C24; functional G22 entry below | Adjacent signed release upgrade, failed canary, rollback/restore boundary and integrated supported failure campaign under continuous identity/operation/data/billing probes. | Full G23 / CR-G23-RESILIENCE and CR-G23-OPERATIONS-ENTRY. Functional G22 proof precedes campaign; human G22 qualification follows in C26. |
| C26 | C25 | Independent engineer completes full incident set, diagnosis, repair, rotation, maintenance and 14-day toil measurement on the accepted candidate. | Full G22 / CR-G22-OPERATIONS. Same release as C25; later runtime change creates a new candidate and repeats affected G23 checks. |
| C27 | C26 | Independently administered bare-metal provider and second engineer reproduce exact public release, install/use/upgrade/failure/restore/cleanup and original product development. | Full G24 / CR-G24-PORTABILITY. Separate outstanding PhoenixNAP site/IaC/GitLab CI commitment must reach accepted protected provider main with its exact core pin and Stage 9; it remains configuration-only and does not claim a PhoenixNAP deployment. Another independently controlled live provider is allowed but does not cancel this obligation. |
| C28 | All C01–C27 | Final adversarial audit, upstream fixes, propagated regressions, public immutable platform/OCS 1.0, support/compatibility/runbooks and exact independent proof. | Full G27 / CR-G27-RELEASE and all remaining standalone 1.0 legacy obligations, Tasks 25–27 and F1–F5. No required unverified blocker, generic private dependency or hidden manual step. |

G25 / CR-G25-CELLS and G26 / CR-G26-FEDERATION retain their complete original
goal files and depend on G27. They are post-1.0 expansion tracks outside C01–C28;
no multi-region or federation claim is created by this sequence.

## G23 entry and release continuity

CR-G23-OPERATIONS-ENTRY explicitly replaces the old requirement that the starting
artifact be called a completed G22 prerelease. Before any C25 campaign, record
verified evidence for **both adjacent immutable signed releases N−1 and N**:

- exact source, artifact, compatibility, SBOM and provenance identities;
- every previously accepted product and journey;
- functional G22 diagnosis, repair, restore, rollback, credential rotation,
  maintenance, telemetry, capacity/fairness, SafePush recovery and incident
  handling needed by the original G23 campaign;
- successful pre-upgrade backup/isolated restore and bounded abort/cleanup.

The original G23 journeys, failures, zero-downtime, direct-origin, RPO/RTO,
provenance and cumulative regression requirements all remain. G22's independent
human walkthrough and 14-day measurement complete in C26 on the same candidate.
Any runtime fix during C26 creates a new candidate, invalidates affected C25
measurements and requires their rerun before G24. G24 requires both full G22 and
G23; G27 remains the final security and 1.0 boundary.

## Coverage and evidence

The table maps every original G goal to a full-qualification owner; all atomic
rows owned by that goal in `COVERAGE.md`, `LEGACY_WORK_MAP.md` and `ISSUE_MAP.md`
inherit that owner without copying or silently rewriting the source requirement.
Shared legacy rows require every applicable owning goal's proof. Early partial
success does not close the original issue. Superseding an obsolete requirement
still requires the accepted replacement, rationale, source and regression
evidence in the original ledger.

The fixed numeric inputs are `measurement-profiles.json`; they do not attest
that any profile passed. Protected evidence binds profile, generator, dataset,
topology and artifact digests using the existing evidence schema. Public source
must never contain private inventory, secrets or unsanitized live evidence.
