# G19 — Controlled access cloud product

## Outcome

Replace shared keys and manual access tickets with a complete OCS product for
short-lived, approved and auditable access to VMs, Kubernetes clusters, consoles
and supported product resources.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Define access request, target, method, approver policy, session, credential,
  recording metadata, revocation, emergency use and retention contracts.
- Issue short-lived SSH certificates/keys, Kubernetes exec credentials, console
  grants and brokered sessions without exposing provider root credentials.
- Enforce IAM, tenant/resource scope, device/user/service attribution,
  just-in-time approval, maximum duration and automatic expiry.
- Implement session status, revocation, evidence/recording references, privacy
  controls and emergency/break-glass integration with G05.
- Meter applicable access/session usage and provide API, CLI, portal extension,
  agent-safe request flow, audit, observability and support diagnostics.
- Implement HA, restart recovery, issuer/key rotation, backup/restore,
  upgrade/rollback and secure removal.

## Required journeys

- request, approve, issue, use, expire and revoke each supported access method;
- prove post-revocation, cross-tenant, wrong-target and unapproved denial;
- interrupt issuer/broker during grant creation and recover without duplicate or
  overlong credential;
- rotate issuer trust while active short sessions follow documented behavior;
- execute emergency access with visible approval/audit and automatic closure;
- restore control state without making historical credentials valid again.

## Hub and downstream delivery

Install the OSS product at the hub and run sessions only against dedicated test
resources. Each downstream supplies bastion/console bindings and retention policy
only; access semantics and credential safety remain public.

## Acceptance

- No supported workflow requires a shared static administrator credential.
- Agent access has the same scope, approval, expiry and audit as human access.
- A control-plane outage cannot extend an expired grant.
- Cleanup removes test credentials/sessions while preserving required audit.
