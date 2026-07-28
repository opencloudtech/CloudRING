# G05 — IAM, workload identity and tenant isolation

## Outcome

Provide comprehensible hierarchical authorization for humans, workloads and
support staff, with fail-closed enforcement at every gateway and executor and
provable isolation among organizations, tenants and projects.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Define provider/region/organization/tenant/project/product/resource hierarchy,
  roles, groups, inheritance, deny precedence and bounded CEL conditions.
- Implement policy CRUD, simulation/explanation, access checks, optimistic
  updates, access review, time-bound grants and change audit.
- Add short-lived service/workload identities, rotation and revocation with a
  SPIFFE-compatible trust model; do not require a new SPIRE deployment until an
  ADR proves its operational value.
- Enforce authorization at public API, portal route, CLI, controller, connector,
  event consumer and data-plane credential broker.
- Implement support grants and break-glass with explicit intent/approval,
  duration, visible banner, immutable audit and automatic revocation.
- Add tenant data/network/resource isolation tests and denial observability that
  does not leak the existence of another tenant's objects.
- Replicate policy, authorization-decision and immutable audit ingestion paths
  across failure domains with bounded caches and explicit stale-policy denial;
  no single replica/node/database connection may become an allow-by-default or
  stop all new eligible decisions.

## Required journeys

- tenant owner invites member, assigns/reviews/removes access and sees effective
  policy explanation;
- own-tenant allow and cross-tenant denial through API, CLI, portal, event and
  executor;
- confused-deputy, stale policy, invalid condition and privilege-escalation paths
  fail closed;
- service identity rotates with no static secret or lost accepted operation;
- support grant denial/allow/expiry and break-glass denial/allow/audit;
- lose one authorization/policy/audit replica and one database connection while
  continuous allow/deny/explanation/audit probes remain correct; failure never
  becomes allow-by-default or loses an acknowledged decision audit.

## Hub and downstream delivery

Deploy complete enforcement to the hub and run the full Task 24 denial matrix
with protected test identities. Downstream repositories contain deployment
bindings only; an independent clean-room consumer uses the same policy,
evaluator, and audit implementation.

## Acceptance

- Public issues #26 and #89 close only after live gateway-and-executor proof.
- No production default selects a memory audit sink or offline verifier.
- IAM decisions remain consistent and explainable across all surfaces.
- Single-replica and single-node loss meet CR-G05-IAM without stale-policy
  fail-open, audit loss or mandatory decision-path outage.
- Management is hidden until authorization and all denial paths are observable.
