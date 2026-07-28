# G02 — Production HA empty provider

## Outcome

An independent company with only public CloudRING can install, operate, upgrade,
roll back and recover a highly available single-region management plane with zero
tenant-visible OCS products installed.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org` through
a side-by-side, reversible cutover.

## Scope

- Complete the public site inventory schema, provider binding SDK, protected
  input resolver, credential broker and generic installer. Downstreams supply
  inventory and bindings only.
- Implement `validate`, `plan`, `apply`, `status`, `upgrade`, `rollback`,
  `diagnose`, `backup`, `restore` and controlled `destroy`.
- Bootstrap supported upstream Kubernetes with executable control-plane, worker
  and gateway configuration and no unresolved placeholders.
- Install and operate management substrate: GitOps, Cilium/Gateway API,
  certificates, OpenBao/External Secrets, PostgreSQL HA, off-cell backup and
  OpenTelemetry-compatible telemetry.
- Provide a narrow durable bootstrap operator/workload identity used only until
  G04/G05, with rotation, revocation, audit and no tenant self-service claim.
- Enforce production topology, failure domains, CSI/snapshot prerequisites,
  quorum, capacity headroom and version compatibility.
- Publish architecture, prerequisites, SLOs, RPO/RTO, backup/restore, maintenance,
  upgrade/rollback and data-retention documentation.

## Required journeys

1. Clean-clone validate, deterministic plan and fresh HA install with no products.
2. Reapply idempotently and compare desired/actual state and artifact digests.
3. Restart/fail one eligible management replica and one worker separately; the
   empty provider remains usable and committed state survives.
4. Back up state, restore into an isolated installation and compare durable state
   and audit identity.
5. Install a signed G02 production candidate, upgrade to a second compatible G02
   candidate, fail a canary, roll back, then complete the good upgrade. A
   development G01 profile must never be silently reclassified as production.
6. Rotate bootstrap credentials/certificates and prove revoked material fails.
7. Exercise controlled destroy only on the disposable clean-room provider.

## Hub and downstream delivery

Install the new foundation beside the current hub with separate cell/namespace,
database, secrets, storage, hostnames and GitOps ownership. Prove coexistence and
that reconciliation cannot adopt/delete current resources. Switch traffic only
after full acceptance; keep the previous revision/data as tested rollback.
Current-alpha migration/removal is a separate approved post-cutover transaction.

The maintained reference deployment supplies its site inventory and bindings
only. An independent downstream runs clean-room validation and planning with
protected or synthetic site inputs and reads no non-public reference path.

## Acceptance

- Fresh public install requires no source edit, private repository or hidden
  manual command and meets the operator-attention measurement profile.
- Every stateful substrate component has HA, backup, restore, monitoring,
  upgrade, rollback and tested failure behavior.
- Issues #32, #83, #85, #92 and #97 close only after exact clean-room and
  side-by-side live proof. The installation part of #93 is proved here, while its
  provider-inventory closure waits for G06; relevant #84/#86 fixes are
  regression-tested.
- Platform readiness is green with an empty catalog; billing is explicitly
  unavailable until G10 and no synthetic billing readiness is claimed here.

## Non-goals

Organizations, human accounts and cloud products begin later. Substrate
components are not customer products and never appear in the catalog.
