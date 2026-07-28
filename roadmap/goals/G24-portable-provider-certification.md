# G24 — Portable provider certification

## Outcome

Certify two independently controlled deployments on the already complete public
interfaces: one maintained reference deployment and one approved disposable
bare-metal installation. This goal adds no new generic installer or platform
engine; any discovered generic defect is fixed in its owning earlier OSS surface.

All reusable fixes must merge into public OSS and the exact accepted change must
be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Audit the maintained reference deployment to only the public pin, site and
  jurisdiction bindings, separately owned extensions and protected evidence;
  generic duplicates zero.
- Audit the independent downstream to only the public pin, its adapters, protected
  inventory, site overlays, ownership, migration and private evidence; no
  non-public reference read.
- Complete independent-site protected inputs/bindings and execute the public G02/G22/
  G23 workflows unchanged: install, operate, backup/restore, upgrade/rollback,
  failure drill and cleanup.
- Discover/adopt or migrate one representative legacy IaaS resource through G06,
  with coexistence, rollback and explicit ownership.
- Build, install, operate, upgrade and remove one independently owned OCS product
  from its own repository and CI using released public artifacts.
- Keep the secondary hosted-metal profile honestly `contract-ready` unless it passes the same real live
  certification; its profile/plan must still pass public conformance.
- Reprove exact gitlinks, SafePush Stage 9, source boundaries and signed release
  artifacts for all consumer mains.

## Required journeys

- clean public plus maintained-reference install/upgrade/rollback and full G23
  regression;
- clean public plus independent-downstream install on a separately controlled
  site, then operate, restore, upgrade/rollback, bounded failure and cleanup;
- two reproducible protected inventory captures with no private data committed;
- independently owned product lifecycle and billing/support path;
- legacy discovery/adoption/migration with rollback;
- explicit secondary-site non-claim or equivalent full certification.

## Acceptance

- A real independent bare-metal environment is a hard gate. Missing hardware, credentials or
  authority blocks G24; synthetic evidence cannot complete it.
- Both downstreams use the same exact accepted public release and have zero
  generic duplicate/private cross-dependency.
- Provider can remove `preflight-and-plan-only` and enable production use only
  after all live gates pass.
- Independent engineers complete site and service workflows without author help.
