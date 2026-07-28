# G17 — Object storage cloud product

## Outcome

Deliver tenant S3-compatible object storage as an OCS product with durable data,
strong isolation, lifecycle policy, usage billing and recoverability. Providers
may use the reference backend or attach an external compatible implementation.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Define account/namespace, bucket, object-access credential, policy, lifecycle,
  versioning, retention/legal-hold and replication contracts.
- Use a maintained S3-compatible backend adapter; provide a Rook/Ceph RGW
  reference and an external-endpoint profile without coupling core to either.
- Implement bucket create/delete, versioning, encryption, policy, CORS, lifecycle,
  retention, credentials and credential rotation.
- Use short-lived or brokered credentials where supported; never expose backend
  administrative credentials to tenants or product UI.
- Meter stored byte-hours, operations and transfer with deduplication and lineage;
  enforce quota/capacity and cost preview.
- Reconcile bucket/backend state, prevent unsafe delete while retained data exists
  and expose explicit force/retention workflows.
- Provide API, CLI, portal extension, S3 endpoint discovery, health/SLO, audit,
  support, backup/replication and upgrade/rollback.

## Required journeys

- create encrypted versioned bucket, issue scoped credential, put/get/list/delete
  objects, rotate/revoke credential, meter and invoice;
- prove cross-tenant and administrative-boundary denial;
- apply lifecycle and retention/legal hold, reject premature destructive delete;
- lose one storage node/gateway and preserve declared availability and data;
- restore metadata and sample objects into isolated scope and compare digests;
- attach a remote object service through OCS and tolerate interruption/reconnect;
- delete all test state according to retention policy.

## Hub and downstream delivery

Install the signed OSS product at the reference site with site-only storage and
DNS bindings. The off-cell backup target must remain failure-independent from the
data under test. An independent downstream runs both local-reference and remote-
adapter conformance with synthetic credentials.

## Acceptance

- Backend topology satisfies documented production requirements; a single-node
  test profile is never promoted as production.
- Credential, retention, encryption and billing semantics are backend-portable.
- Object storage used for platform backups is explicitly separated from tenant
  product state and failure claims.
