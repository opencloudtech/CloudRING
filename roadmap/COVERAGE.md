# Legacy Goal 01 coverage bridge

This file preserves one-to-one coverage for the stable requirement definitions in
[`specifications/goal-01.md`](../specifications/goal-01.md), but it no longer
records accepted delivery status. The former Goal 01 combined
reference-installation recovery, public contracts and later platform work into
one scheduling unit; the canonical executable program is now
[`roadmap.yaml`](roadmap.yaml), with accepted state under [`state/`](state/).

Ownership is carried without weakening through
[`LEGACY_WORK_MAP.md`](LEGACY_WORK_MAP.md). Each row below names exactly one
canonical owner and the stable `CR-GNN-*` requirement against which it is now
accepted. The legacy identifier remains a compatibility alias, not a second
status or completion authority. Every row stays `unverified` until that
canonical goal publishes an exact public/reference/downstream release tuple and fresh
evidence. Historical local or live observations are recovery inputs, not
readiness claims.

## Goal 01 — Reference-cell critical-path survivability

| Legacy requirement | Canonical owner | Canonical requirement | Goal 01 acceptance slice | Status | Evidence |
| --- | --- | --- | --- | --- | --- |
| CR-FND-040 | G03 | CR-G03-KERNEL | Replaceable state, backup, and reconciliation boundaries | unverified | pending durable-kernel boundary proof |
| CR-FND-050 | G00 | CR-G00-DELIVERY | Public reusable core separated from concrete provider deployment | unverified | pending source-boundary and downstream-pin audit |
| CR-FND-120 | G27 | CR-G27-RELEASE | No production-readiness claim beyond the proved one-cell envelope | unverified | pending final release-envelope gate |
| CR-FND-130 | G00 | CR-G00-DELIVERY | Evidence before readiness; missing/stale stays blocked | unverified | pending fail-closed evidence-path proof |
| CR-FND-140 | G03 | CR-G03-KERNEL | Canonical operation identity binds state and audit probes | unverified | pending durable-operation identity proof |
| CR-STO-080 | G18 | CR-G18-BACKUP | Platform backup control plane for declared Goal 01 classes | unverified | pending integrated backup-control proof |
| CR-STO-090 | G23 | CR-G23-RESILIENCE | Fresh signed backup barrier before every mutation wave | unverified | pending signed pre-mutation barrier campaign |
| CR-STO-100 | G18 | CR-G18-BACKUP | Isolated restore drill blocks promotion | unverified | pending restore, validation, and cleanup receipt |
| CR-STO-110 | G18 | CR-G18-BACKUP | RPO/RTO declared for every critical state class | unverified | pending measured survivability inventory |
| CR-STO-130 | G23 | CR-G23-RESILIENCE | etcd off-cell snapshot and exact restore | unverified | pending integrated exact-restore receipt |
| CR-STO-140 | G18 | CR-G18-BACKUP | Fresh, fail-closed durability evidence states | unverified | pending backup-product evidence-state proof |
| CR-STO-150 | G23 | CR-G23-RESILIENCE | Storage-dependent node drains interlocked with the barrier | unverified | pending server-loss and drain campaign |
| CR-STO-160 | G18 | CR-G18-BACKUP | Offsite immutable copies and retention-delete denial | unverified | pending off-cell immutability proof |
| CR-K8S-020 | G23 | CR-G23-RESILIENCE | Three-member control-plane continuity under one-server loss | unverified | pending sequential one-server-loss campaign |
| CR-K8S-030 | G23 | CR-G23-RESILIENCE | etcd backup and restore | unverified | pending integrated backup/restore campaign |
| CR-K8S-090 | G02 | CR-G02-HA-INSTALL | Declared cluster add-ons owned and reconciled through GitOps | unverified | pending zero-unmanaged ownership audit |
| CR-K8S-130 | G23 | CR-G23-RESILIENCE | Node lifecycle operations preserve workload continuity | unverified | pending node lifecycle continuity campaign |
| CR-OCS-140 | G07 | CR-G07-OCS-RC | Durability surfaces and restore objectives remain explicit | unverified | pending canonical OCS conformance proof |
| CR-OPS-090 | G22 | CR-G22-OPERATIONS | Dated pre-state, rollback, abort, post-state, and cleanup per wave | unverified | pending operator workflow receipts |
| CR-OPS-180 | G22 | CR-G22-OPERATIONS | Disaster-recovery drill calendar starts with a real restore | unverified | pending real restore and scheduled next-due proof |
| CR-DPL-040 | G22 | CR-G22-OPERATIONS | Dry-run-first desired state reconciles controlled drift | unverified | pending guided drift-repair proof |
| CR-DPL-050 | G02 | CR-G02-HA-INSTALL | Reference environment self-reconciles from its signed Git source | unverified | pending signed GitOps source proof |
| CR-DPL-150 | G23 | CR-G23-RESILIENCE | Mixed-version-safe database migration discipline | unverified | pending signed N-1-to-N migration/rollback proof |

Requirements for the local or remote OCS runtime, dynamic microfrontends, product
moderation, offers, entitlements, quota, billing, marketplace, multi-cell operation,
and federation are not owned by Goal 01 and remain pending for later roadmap goals.
