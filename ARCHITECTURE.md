# CloudRING architecture index

CloudRING is an open provider-control-plane project with independently operated
cloud products connected through the Open Cloud Standard (OCS). Architecture
documents describe intended boundaries; only implemented code, tests, released
artifacts, and current evidence can establish delivery.

## Read in this order

1. [Repository map](REPOSITORY_MAP.md) — source layout, ownership, maturity, and
   source-of-truth locations.
2. [Target architecture](roadmap/TARGET_ARCHITECTURE.md) — the intended provider
   management plane, regional cells, product data planes, and OCS boundary.
3. [Product architecture invariants](docs/product-architecture-invariants.md) —
   stable capability, identity, lifecycle, billing, durability, and extension
   rules.
4. [OCS architecture](docs/architecture.md) — how platform and product teams
   integrate without importing each other's implementation.
5. [Provider adapters](docs/provider-adapters.md) and
   [site installation contract](docs/provider-site-installation.md) —
   provider-neutral infrastructure boundaries.
6. [Public current state](roadmap/CURRENT_STATE.md) — which slices are
   implemented, reference-only, experimental, blocked, or planned.

## Durable boundaries

- Reusable platform behavior, contracts, SDKs, validators, reference modules,
  deployment bases, tests, and public documentation belong here.
- Provider accounts, credentials, private inventory, customer or tenant data,
  private endpoints, installation-specific values, and live operational evidence
  do not belong here.
- Products integrate through versioned OCS packages and APIs. Platform core does
  not import product internals.
- Provider integrations use adapters and site profiles. A concrete provider
  account or topology is not a platform invariant.
- API, CLI, portal, and agent-safe automation are clients of the same
  authorization and operation model.

## Availability boundary

The repository currently contains three-member control-plane fixtures,
three-node storage/reference profiles, and a one-server-loss observer. They are
reference material for a declared single-failure test envelope, not a universal
production topology.

The planned portable contract will express availability through failure domains,
etcd/database quorum, workload and storage replication, endpoint continuity,
RPO/RTO, and measured SLOs. That contract remains planned. This documentation
does not generalize the runtime or claim that current reference profiles satisfy
arbitrary topologies.

## Authority

[`roadmap/roadmap.yaml`](roadmap/roadmap.yaml) is the single canonical delivery
graph and status index. Architecture documents may constrain a goal but cannot
advance its status. See the [repository lifecycle](docs/repository-lifecycle.md)
for document maturity and retirement rules.
