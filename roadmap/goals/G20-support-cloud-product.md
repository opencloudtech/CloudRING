# G20 — Support cloud product

## Outcome

Make customer support a first-class OCS product: entitlement-aware cases,
privacy-safe diagnostics, bounded collaboration and a durable incident timeline
instead of ad hoc access and untraceable messages.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Define support offering/entitlement, case, severity, SLA clock, resource link,
  consent, escalation, diagnostic request, collaboration, resolution and
  retention contracts.
- Generate redacted support bundles with manifest, digest, provenance, size/
  cardinality limits and source-safety validation.
- Integrate G19 controlled access for bounded diagnostic sessions; support can
  never mint hidden or longer-lived access.
- Implement tenant/provider comments/events, status, SLA alerts, ownership,
  handoff, escalation and immutable audit.
- Support external ticket-routing adapters without making a proprietary system a
  core dependency.
- Provide customer/provider API, CLI, portal extension, observability,
  backup/restore, upgrade/rollback and secure retention/deletion.

## Required journeys

- open entitled case, attach resources, request/consent to diagnostics, collect
  bundle, grant/revoke access, escalate, resolve and retain/delete by policy;
- reject cross-tenant case/resource/bundle access and unsupported entitlement;
- fail external routing and continue durable local support operation;
- generate a source-safe bundle under five minutes with no secret/private data;
- restore case/audit state and prove no access grant is resurrected;
- meter/rate a paid support offering without corrupting SLA clocks.

## Hub and downstream delivery

Install the OSS product at the hub with an isolated support route and test tenant.
Each downstream supplies routing, ownership and jurisdictional retention
configuration only. Complete cleanup preserves only policy-required audit.

## Acceptance

- Support cannot bypass G05 IAM or G19 access policy.
- Every critical case has owner, clock, escalation and externally visible state.
- Diagnostic redaction is machine-tested and fail-closed.
- External routing outage does not lose or duplicate a case.
