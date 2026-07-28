# G25 — Post-1.0 regional cells, multi-region and measured scale

## Outcome

Let a provider grow by adding bounded, independently deployable cells and regions
instead of enlarging one control plane forever. Scale, residency and blast radius
are measured and visible.

This is an explicit post-1.0 expansion track. A complete single-region provider
is the released prerequisite; lack of second-region capacity cannot block or
weaken CloudRING 1.0.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Define cell identity/capacity, tenant placement, regional residency, health,
  failure isolation, version ring and evacuation/migration contracts.
- Keep regional transactional/product state in its owner cell; replicate only
  explicitly designed global directory/control data.
- Add cells/regions from the exact G27 release artifacts, using the stable
  installer contract introduced in G02, and deploy, upgrade, roll back and fail
  them independently.
- Implement region/cell discovery, routing, quota/capacity placement and explicit
  tenant choice without assuming shared database, Kubernetes or storage.
- Add tenant/resource movement only with stated consistency, data transfer,
  downtime, rollback and billing semantics.
- Load each cell to its versioned envelope, enforce backpressure/fairness and
  prove the scale-efficiency formula in `MEASUREMENT_CONTRACT.md`.
- After the functionality is complete, run a dedicated broad adversarial and
  supply-chain review, fix every release blocker and repeat the full G25
  regression before promotion; this post-1.0 track cannot reuse G27's earlier
  review as proof for new multi-cell or multi-region behavior.

## Required journeys

- add a second cell, place new tenants and fail/upgrade/rollback it independently;
- overload one cell/tenant and preserve system and other-cell SLOs;
- migrate an eligible tenant/resource with explicit data/disruption contract and
  rollback before the point of no return;
- add a real second region after explicit capacity approval, enforce residency and
  prove no silent cross-region data movement;
- lose regional management connectivity while existing product data planes run;
- publish hardware/workload profiles, saturation, headroom and first bottleneck.

## Hub and downstream delivery

Deploy cell-aware management to the hub, add at least a second isolated cell and
connect a real second region after explicit cost approval. Missing approved
capacity blocks G25; synthetic topology cannot complete it. The independent
downstream repeats cell conformance on its certified deployment; no shared
reference-deployment state is used.

## Acceptance

- Two cells provide at least the documented scale efficiency at the same SLO.
- Two real regions pass placement, residency, isolation and independent-failure
  proof; the platform can still operate a deliberately single-region provider.
- Failure/upgrade blast radius is limited to the target cell.
- Residency, placement and movement are durable, auditable and customer-visible.
- No unqualified “hyperscale” claim exists without profile-bound evidence.
- The G25 security finding ledger has no unresolved release blocker, all fixes
  are retested and the final full regression is green on the promoted artifacts.
