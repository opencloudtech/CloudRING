# G13 — Volume cloud product

## Outcome

Provide tenant block storage as a complete OCS product: durable volumes,
attachments, snapshots, resize, performance classes, encryption, backup linkage
and failure recovery.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Define volume, attachment, snapshot, storage class and performance/capacity
  contracts with clear lifecycle and failure semantics.
- Implement generic CSI-oriented connector behavior and a production reference
  adapter using a maintained HA storage backend. The reference backend must
  satisfy its documented multi-node failure-domain requirements.
- Support create, attach, detach, online/offline resize, snapshot, clone, restore,
  retain/delete policy and secure deprovisioning.
- Implement per-tenant keys or key hierarchy, encryption at rest/in transit where
  applicable, credential rotation and access revocation.
- Meter allocated capacity, provisioned performance, snapshots and data transfer;
  enforce quota, reservation and backend capacity safety thresholds.
- Reconcile CSI/backend state, detect leaked/stale attachments, prevent multi-
  attach corruption and expose repair operations.
- Provide API, CLI, portal extension, health, SLOs, alerts, support bundles,
  backup/restore and upgrade/rollback.

## Required journeys

- provision, attach, write digest, detach, reattach elsewhere and verify digest;
- resize, snapshot, clone and restore to an isolated resource;
- reject cross-tenant attach/read and incompatible access mode;
- lose one storage/compute node and prove supported-volume availability and data;
- interrupt provision/delete and reconcile without leaked backend objects;
- rotate access/key material without losing availability;
- meter, rate, invoice and trace storage usage.

## Hub and downstream delivery

Install the OSS volume product on the reference site using site-only device and
topology bindings. Run destructive drills only on dedicated test resources. An
independent downstream validates prerequisites and plan against synthetic storage
inventory; it must not depend on the reference site's provider code.

## Acceptance

- CSI drivers, snapshot CRDs/controllers and backend versions are pinned and
  installed on a fresh environment. Issue #96 closes by live proof; #90 remains
  open until G18 proves the backup integration over this snapshot path.
- Production mode refuses replication-one or unknown failure-domain topology.
- Backup and isolated restore prove data, ownership, encryption and cleanup.
- Product removal preserves or deletes data only according to explicit policy.
