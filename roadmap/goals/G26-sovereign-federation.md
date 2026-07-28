# G26 — Post-1.0 sovereign federation

## Outcome

Two independent providers with separate trust roots, administrators, databases
and jurisdictions can exchange an approved product through an OCS Federation
release candidate without a shared root or mandatory central coordinator.

This is an opt-in post-1.0 expansion track. A standalone provider remains fully
functional without federation, multi-region, a public directory or any central
CloudRING service.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Establish provider identity, trust negotiation/rotation, relationship policy,
  discovery and revocation using signed manifests and replay protection.
- Exchange catalogs, offers, availability, moderation and jurisdiction/residency
  metadata under explicit provider opt-in.
- Implement cross-provider identity linkage/consent, order, entitlement, remote
  attachment, lifecycle, usage, support and immutable audit.
- Implement partition-safe store-and-forward, idempotent reconnect, conflict,
  expiration and relationship termination.
- Implement runnable reconciliation, commission calculation, corrections,
  dispute state and cross-provider entitlement/settlement ledgers. Terminal
  clearing and payment remain replaceable external adapters.
- Implement an explicit private-cloud peak-capacity journey that can burst an
  approved workload to a consenting public peer. A bound quote and bilateral
  consent must pass residency, identity/IAM, quota/capacity and cost policies
  before reservation; provision, scale, suspend/resume and deprovision use the
  normal remote lifecycle, reconcile usage and settlement exactly once, and
  provide compensating rollback when any precondition or remote operation fails.
- Publish Federation release-candidate positive/negative conformance and
  compatibility with OCS 1.0. Federation receives its own broad adversarial
  review and release gate after this functionality is complete; it cannot
  retroactively change or weaken the standalone OCS 1.0 contract.

## Required journeys

- upgrade both G24-certified sovereign providers and the selected G21 product to
  the exact G27 release tuple, then mutually approve that product;
- remote discover/order/provision/use/meter/rate/reconcile, produce adapter-ready
  settlement instructions, support and deprovision;
- from a capacity-constrained private cloud, request a priced burst from a
  consenting public peer, bind quote and both consents, enforce residency,
  identity/IAM, quota and cost policy, provision and scale the remote workload,
  meter/reconcile/settle it, then drain and deprovision it; reject or interrupt
  each phase and prove idempotent compensation, rollback and local continuity;
- partition both directions, continue allowed local work, reconnect exactly once
  and reconcile state/financial ledgers;
- rotate/revoke trust and terminate relationship without harming local products;
- reject forged, replayed, stale, unauthorized, incompatible and residency-
  violating messages;
- remove any optional discovery/coordination service and prove existing peers
  continue according to the contract.

## Hub and downstream delivery

Use two G24-certified independent providers only after both run the exact G27
release tuple; G24 is provider provenance, not the post-1.0 execution base.
Neither provider is embedded in the other's repository or administration. Any
public directory is optional/cacheable and never the authorization root.

## Acceptance

- No shared database, root identity, mandatory coordinator or hidden non-public
  dependency exists.
- Partition/reconnect and negative security conformance pass with real operations.
- Provider policy and legal control remain local and auditable.
- Peak-capacity federation cannot reserve, run or bill remote resources without
  a valid quote, bilateral consent and all local/remote policy decisions; its
  lifecycle, reconciliation, rollback and settlement are terminally verifiable.
- Unaffected providers/products remain usable when one provider disappears.
- No company, jurisdiction, directory, coordinator or trust root can disable
  already established independent peers as a whole.
