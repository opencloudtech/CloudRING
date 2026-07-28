# G04 — Human identity and account lifecycle

## Outcome

Ship a production built-in identity provider so an independent CloudRING provider
works without buying another identity product, while also supporting federation
with external OIDC and directory sources.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Implement OIDC discovery, authorization-code flow with PKCE, client lifecycle,
  token issuance/validation/rotation and standards-compliant logout.
- Implement registration/invitation/provisioning, verified contact workflow,
  passkeys/WebAuthn, MFA policy, lockout protection, recovery, disable/delete and
  privacy/retention controls.
- Implement secure server-side sessions, refresh rotation, family revocation,
  device/session view, risk events and CSRF/session-fixation defenses.
- Support external OIDC federation and G03 directory synchronization with issuer,
  key and outage handling; external identity cannot bypass local account policy.
- Provide account/profile/security UI, public APIs/CLI where appropriate, admin
  recovery and durable privacy-safe audit.
- Run replicated serving components, key rotation, backup/restore, upgrade/
  rollback, monitoring and support diagnostics.

## Required journeys

- register or provision, verify, enroll passkey/MFA, login, refresh and logout;
- reject token after logout and reject expired, wrong issuer/audience/nonce and
  excessive-assurance inputs;
- rotate signing keys with overlapping validation and recover from IdP outage;
- perform account recovery without account takeover and revoke all sessions;
- link/unlink an external identity with collision and takeover negative tests;
- disable/delete account under retention policy and prove access denial/audit;
- fail an identity replica/database connection during active sessions.

## Hub and downstream delivery

Replace synthetic/offline identity readiness at the hub. Run sanitized browser
and API journeys with protected test accounts and cleanup. Downstream operators
supply only mail, external-IdP, and secret bindings; an independent clean-room
consumer runs identical identity conformance.

## Acceptance

- Built-in identity works from public artifacts with no private dependency.
- Public issue #25 closes only after the G03 durable organization graph and this
  goal's real external identity/source lifecycle pass failure and scale proof.
- Logout/revocation, recovery and key rotation are live-proved and durable.
- No management or tenant surface becomes visible merely because a token parses.
- Documentation states supported OIDC/WebAuthn versions and privacy boundaries.
