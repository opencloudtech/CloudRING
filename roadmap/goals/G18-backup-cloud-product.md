# G18 — Backup cloud product

## Outcome

Provide verified backup and recovery as a complete OCS product for VM, managed
Kubernetes, volumes, object metadata and product-specific state. Customers can
request protection and prove recovery without an operator ticket.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Define policy, schedule, scope, consistency, restore point, retention,
  immutability, legal hold, off-cell target, verification and cleanup contracts.
- Implement adapters for Kubernetes/Velero, CSI snapshots, VM and product hooks;
  application consistency and unsupported data are explicit.
- Encrypt in transit/at rest, broker target credentials, rotate/revoke access and
  prevent the protected system from deleting immutable copies.
- Implement real backup, inventory, isolated restore, data/ownership validation,
  periodic restore rehearsal and failed/incomplete backup diagnosis.
- Meter stored byte-hours, operations and transfer; enforce quota/capacity and
  cost preview through G09/G10.
- Provide API, CLI, portal extension, agent-safe plans, audit, SLOs, alerts,
  support bundles, upgrade/rollback and retention-aware deletion.

## Required journeys

- protect representative VM, Kubernetes, volume and object metadata, create
  off-cell copies, restore into isolation, compare digests/ownership and clean;
- tolerate transient APIs, multiple uploads, clock skew, partial snapshot and
  target interruption without false success;
- prove cross-tenant restore denial and that restored credentials are rotated;
- expire retention normally and reject premature destruction/legal-hold removal;
- restore backup control state after database failover and continue schedules;
- meter/rate/invoice protection and correction events without duplicates.

## Hub and downstream delivery

Install the signed OSS product at the reference site with site-only target
bindings. The target must be failure-independent from protected data. An
independent downstream uses its own target binding and the same lifecycle and
conformance.

## Acceptance

- Task 22 is re-proved; the remaining backup-integration part of #90 and all of
  #91 close only after these current product paths pass live restore proof.
- Success requires data retrieval and validation, never a manifest/snapshot alone.
- Published RPO/RTO are measured using `MEASUREMENT_CONTRACT.md`.
- Restore and cleanup are routine, idempotent and fully audited.
