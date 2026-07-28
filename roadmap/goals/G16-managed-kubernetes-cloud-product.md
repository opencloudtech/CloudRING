# G16 — Managed Kubernetes cloud product

## Outcome

Provide tenant Kubernetes clusters as a complete OCS product. Customers can
create, access, scale, upgrade, back up, recover and delete conformant clusters
without provider tickets.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Define cluster, control plane, machine pool, version, network, storage class,
  credential and maintenance policy contracts.
- Use Cluster API and supported bootstrap/control-plane providers as the generic
  lifecycle model. The reference infrastructure provider may use KubeVirt, but
  product APIs cannot expose that dependency as universal.
- Implement create, scale, repair, credential rotation, version upgrade,
  maintenance, backup, restore and delete with durable Operations and rollback
  barriers.
- Integrate Network, Volume, Image and VM products through infrastructure-user
  entitlements and explicit cost attribution.
- Provide tenant OIDC/IAM mapping, short-lived kubeconfig/exec credentials,
  API endpoint protection, audit and isolation from provider management cluster.
- Install and verify CNI, CSI, DNS, metrics and supported add-ons from signed,
  versioned profiles; avoid an unbounded add-on marketplace in this goal.
- Meter control plane, nodes, storage, addresses and transfer; enforce quota,
  capacity and version support.
- Provide API, CLI, portal extension, health/SLO, diagnostics and support bundles.

## Required journeys

- create a cluster, obtain short-lived access, deploy workload, expose it,
  persist data, scale nodes and observe cost;
- rotate access and certificates, revoke a user and prove denial;
- upgrade control plane and nodes through N-1 to N with workload continuity and
  rollback before the documented point of no return;
- lose one worker and one eligible control-plane instance in separate drills;
- back up and restore a tenant workload/data into isolated scope;
- delete the cluster and all owned dependencies without deleting shared assets;
- prove one tenant cannot reach another tenant or provider management plane.

## Hub and downstream delivery

Install the OSS product on the reference platform and create a dedicated tenant
cluster using reference products only. Clean it up after the complete lifecycle.
An independent downstream validates the same product against its provider adapter
without any non-public reference files.

## Acceptance

- Rendered workload-cluster bootstrap is executable and documented; the G02
  regressions for issues #83, #85, #92, #93 and #97 remain green against this
  product path rather than being closed a second time.
- Kubernetes version skew, deprecation and add-on compatibility are enforced.
- Cluster API and product controllers recover from restart and stale caches.
- No static kubeconfig or long-lived tenant credential is stored in evidence.
