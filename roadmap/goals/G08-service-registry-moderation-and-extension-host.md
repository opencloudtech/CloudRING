# G08 — Service registry, moderation and extension host

## Outcome

Providers can safely discover, review, approve, install, expose, upgrade, disable
and remove independently developed OCS products. A product team can ship API and
portal updates without changing platform core, while provider policy remains in
control.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Implement a durable product/package registry that actually installs and
  operates packages rather than only validating metadata.
- Add admission and moderation: ownership, licence, signature, vulnerability,
  compatibility, requested permissions, data residency, support and operational
  readiness review.
- Make publisher commercial eligibility a machine-enforced admission state. A
  paid offering or public exposure requires the exact approved publisher,
  agreement/legal terms, jurisdiction and payout-enablement revision; expiry,
  suspension or revocation fails closed without silently changing an existing
  customer's retention or recovery rights.
- Model product, package revision, offering, provider-only, named-principal,
  tenant, cohort/group and public audiences, region/cell availability, rollout
  channel, entitlement prerequisites and deprecation.
- Implement staged activation, canary audience, pause, rollback, revision history,
  uninstall and data-retention decisions.
- Build a capability-scoped provider API gateway extension mechanism. Products
  declare only the API routes/events they own; authorization remains centralized
  and rechecked by the connector.
- Select through an ADR and implement an optional signed, sandboxed portal
  extension model with same-origin mediation, CSP, explicit capabilities,
  version compatibility, error isolation and accessible navigation. An API-only
  product remains installable and fully manageable without UI. Unsigned remote
  JavaScript must not receive provider credentials.
- Give administrators portal/API/CLI workflows for moderation, policy, audiences,
  regions, rollout status, health, support and removal.

## Required journeys

- publish signed package, inspect requested capabilities, approve for a private
  or named audience in selected regions, activate, widen to a cohort or public,
  upgrade, roll back and remove;
- evaluate overlapping audience rules, membership change, region mismatch and
  policy backend failure; visibility and access remain fail closed and auditable;
- reject bad signature, licence incompatibility, excessive IAM, invalid UI/API,
  vulnerable dependency and incompatible OCS version;
- crash or hang a product UI/API and prove the provider portal and other products
  remain usable;
- revoke a package or signing identity and prevent new activation while preserving
  an explicit operator recovery path;
- attempt paid or public activation with missing, stale, mismatched, suspended
  and revoked publisher eligibility/agreement/legal/payout state; every attempt
  fails closed on the exact machine-readable reason and is auditable;
- install zero products and prove platform readiness remains green.
- install and operate an API-only remote product without mounting a portal
  module, while API/CLI/agent capability remains complete.

## Hub and downstream delivery

Deploy the registry, moderation console, gateway and extension host to the hub.
Use the G07 tutorial and independently built clean-room package in isolated
audiences. Install, activate, upgrade, fail/roll back and remove both; the public
catalog remains honest until G12 delivers the first sellable product. The
The independent path uses only released public SDK/packages and its own
clean-room CI.

## Acceptance

- Registry state is durable, HA, auditable, backed up and restored.
- Package code cannot gain undeclared platform, tenant or browser capabilities.
- Rollout and rollback are observable and preserve unrelated products.
- Documentation lets an external provider define its own moderation policy.
- Every paid or public activation receipt binds the immutable package revision
  to the exact approved publisher commercial-eligibility revision.
- Touched downstream OCS registry/extension duplicates are removed after the
  public replacement lands; only site bindings remain.
