# CloudRING implementation roadmap

This directory is the executable program for turning CloudRING into a complete,
independently operable open-source cloud platform. It replaces a single
breadth-first mega-goal with an ordered series of production vertical releases.

The intended end state is a provider platform that:

- can be installed, upgraded, operated, backed up and recovered by one engineer;
- has no single point of failure inside its declared failure domain;
- lets a mid-level developer build and operate a cloud product without changing
  platform core;
- exposes the same complete capability through API, CLI, portal and safe agent
  automation;
- runs with zero installed cloud products and accepts products only through the
  Open Cloud Standard (OCS);
- scales by adding replicas and bounded regional cells rather than by making one
  unbounded control plane;
- keeps all reusable implementation in `opencloudtech/CloudRING` and keeps only
  site, provider and proprietary bindings in downstream repositories;
- is continuously delivered to the OpenCloudTech reference installation at
  `hub.cloudring.org`.

## How to execute this roadmap

Read, in order:

1. [CURRENT_STATE.md](CURRENT_STATE.md) for the audited starting point.
2. [TARGET_ARCHITECTURE.md](TARGET_ARCHITECTURE.md) for durable design
   boundaries.
3. [EXECUTION_CONTRACT.md](EXECUTION_CONTRACT.md) for agent, delivery and
   acceptance rules.
4. [MEASUREMENT_CONTRACT.md](MEASUREMENT_CONTRACT.md) for reproducible SLO,
   performance, operator-toil and developer-DX proof.
5. [EVIDENCE_POLICY.md](EVIDENCE_POLICY.md) for resolvable, signed and expiring
   proof.
6. [VERIFICATION_MATRIX.md](VERIFICATION_MATRIX.md) for executable terminal
   goal QA and machine-readable verdicts.
7. [ISSUE_MAP.md](ISSUE_MAP.md), [LEGACY_WORK_MAP.md](LEGACY_WORK_MAP.md) and
   [HUB_PREREQUISITES.md](HUB_PREREQUISITES.md) for ownership and live gates.
8. [REFERENCES.md](REFERENCES.md) for the standards and primary sources used.
9. The next goal whose dependencies are all complete.

`roadmap.yaml` is the machine-readable dependency graph and compact status index.
Goal files are the normative acceptance contracts. Once a goal starts, its
detailed proof record is stored under `state/` against `state.schema.json`; proof
artifacts use `evidence.schema.json`. CI must keep the index and detailed state in
lockstep. Current SHAs and runtime facts are deliberately kept out of individual
goals so that a stale snapshot cannot become a release claim.

## Delivery graph

| ID | Goal | User or operator value delivered |
| --- | --- | --- |
| G00 | [Truthful baseline and protected delivery](goals/G00-truthful-baseline-and-protected-delivery.md) | A clean, lossless and enforceable path from code to all mains and the live reference installation. |
| G01 | [Disposable public development installation](goals/G01-disposable-public-development-installation.md) | Contributors and product teams get a one-command, isolated, real development cloud. |
| G02 | [Production HA empty provider](goals/G02-production-ha-empty-provider.md) | An independent company can install and operate the production platform before choosing products. |
| G03 | [Durable resource and operation kernel](goals/G03-durable-resource-and-operation-kernel.md) | Reliable organizations, tenants, projects, resources and asynchronous operations. |
| G04 | [Human identity and account lifecycle](goals/G04-human-identity-and-account-lifecycle.md) | Secure registration, authentication, sessions, recovery and external identity federation. |
| G05 | [IAM, workload identity and tenant isolation](goals/G05-iam-workload-identity-and-tenant-isolation.md) | Comprehensible least privilege and fail-closed isolation at every execution boundary. |
| G06 | [Provider inventory, adoption and operation execution](goals/G06-provider-inventory-adoption-and-operation-execution.md) | Providers safely discover, adopt and mutate infrastructure without ambiguity. |
| G07 | [OCS release-candidate developer platform](goals/G07-open-cloud-standard-release-candidate.md) | Independent teams can build and falsify evolving service contracts before 1.0 freeze. |
| G08 | [Service registry, moderation and extension host](goals/G08-service-registry-moderation-and-extension-host.md) | Providers safely install, approve, expose, upgrade and remove signed products. |
| G09 | [Orders, subscriptions, lifecycle, quota and capacity](goals/G09-orders-subscriptions-lifecycle-quota-and-capacity.md) | Product lifecycle is durable and capacity-safe before money is charged. |
| G10 | [Metering, rating and billing](goals/G10-metering-rating-and-billing.md) | Providers can sell products and customers can understand and control cost. |
| G11 | [Unified human and agent experience](goals/G11-unified-human-and-agent-experience.md) | Portal, API, CLI and AI agents use one safe and consistent control surface. |
| G12 | [Network cloud product](goals/G12-network-cloud-product.md) | Isolated dual-stack tenant networks and connectivity are delivered through OCS. |
| G13 | [Volume cloud product](goals/G13-volume-cloud-product.md) | Durable block volumes, snapshots, resize and recovery become an OCS product. |
| G14 | [Image and artifact cloud product](goals/G14-image-and-artifact-cloud-product.md) | Trusted VM and OCI artifacts are imported, scanned, signed and distributed. |
| G15 | [Compute VM cloud product](goals/G15-compute-vm-cloud-product.md) | A complete, billed and recoverable VM lifecycle is available through OCS. |
| G16 | [Managed Kubernetes cloud product](goals/G16-managed-kubernetes-cloud-product.md) | Tenants create, upgrade, recover and delete conformant Kubernetes clusters. |
| G17 | [Object storage cloud product](goals/G17-object-storage-cloud-product.md) | Tenants receive a durable, metered and policy-controlled S3-compatible product. |
| G18 | [Backup cloud product](goals/G18-backup-cloud-product.md) | Verified off-cell backup and isolated recovery become customer self-service. |
| G19 | [Controlled access cloud product](goals/G19-controlled-access-cloud-product.md) | Short-lived approved resource access replaces shared credentials and tickets. |
| G20 | [Support cloud product](goals/G20-support-cloud-product.md) | Cases, diagnostics and bounded support access become an auditable product. |
| G21 | [External integration product](goals/G21-external-integration-product.md) | One real remote system proves replaceable OCS integration; other profiles remain templates. |
| G22 | [One-engineer operations and autonomous recovery](goals/G22-one-engineer-operations-and-autonomous-recovery.md) | Cross-product operations meet a measured one-engineer toil budget. |
| G23 | [Zero-downtime upgrades and failure resilience](goals/G23-zero-downtime-upgrades-and-failure-resilience.md) | The integrated platform survives supported failures and released upgrades. |
| G24 | [Portable provider certification](goals/G24-portable-provider-certification.md) | Two independently controlled environments deploy the same public release without non-public platform dependencies. |
| G27 | [Final security, compliance and 1.0 release](goals/G27-final-security-compliance-and-1-0-release.md) | The fully audited platform and OCS 1.0 are released for independent providers. |
| G25 | [Regional cells, multi-region and measured scale](goals/G25-regional-cells-multi-region-and-scale.md) | Post-1.0: providers add bounded scale/failure units without enlarging one control plane forever. |
| G26 | [Sovereign federation](goals/G26-sovereign-federation.md) | Post-1.0: independent providers exchange approved products without shared root, database or coordinator. |

## Sequencing rule

Goals execute in the dependency order encoded in `roadmap.yaml`. The CloudRING
1.0 path ends at G27 after G24; it does not depend on G25 multi-region or G26
federation. Those post-1.0 tracks depend on the released standalone provider and
may proceed independently of each other. Research, design spikes and read-only
audits for a later goal may run early, but production implementation cannot skip
its declared dependencies. This prevents parallel scaffolds, duplicate platform
kernels and an unmaintainable partial system without making future federation a
release blocker.

Every goal must finish the same delivery chain:

`OSS implementation -> OSS main -> downstream pins -> downstream mains ->
hub.cloudring.org rollout -> live acceptance -> issue closure -> evidence`

A goal is not complete when it is only documented, locally implemented, green in
a feature branch, or present in an open PR/MR.

## End of roadmap

CloudRING 1.0 is complete only after G27 proves, from released artifacts and clean
checkouts, that independent providers can install and operate CloudRING, product
teams can build conformant local, remote and API-only services without core
changes, the required reference products work through OCS, upgrades and declared
failures preserve service, and no required capability remains a scaffold, mock,
private dependency or hidden manual step. G25 and G26 are explicit post-1.0
expansion tracks and cannot be used to weaken or substitute any standalone 1.0
requirement.
