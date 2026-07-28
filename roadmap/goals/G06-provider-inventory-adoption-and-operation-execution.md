# G06 — Provider inventory, adoption and operation execution

## Outcome

Providers can discover infrastructure, understand drift, explicitly adopt
existing resources and execute safe mutations without ambiguous ownership or
one-off downstream scripts. This is the runtime foundation OCS lifecycle uses.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Define provider-neutral inventory, observation, ownership, drift, adoption,
  plan, approval, execution, receipt and reconciliation contracts.
- Implement read-only discovery before mutation; expose unknown, unmapped, stale,
  conflicting and externally managed resources.
- Require explicit adoption with identity, scope, expected state, rollback and
  non-interference proof; never silently claim external assets.
- Implement durable plan/apply Operations with least-privilege credential broker,
  idempotency, optimistic preconditions, timeouts, retry classification,
  ambiguous-result reconciliation, compensation and cleanup.
- Separate generic executor from provider adapters. Prove it against at least two
  independently implemented adapters, one public reference and one downstream;
  neither adapter may supply missing generic behavior.
- Add capacity observation, rate limits, backpressure, audit, metrics, traces,
  support diagnostics and upgrade compatibility.

## Required journeys

- discover without mutation and compare two repeatable inventory captures;
- show unknown/unmapped/stale resources and reject unsafe implicit adoption;
- approve/adopt one resource and relinquish it without destructive side effects;
- plan/apply/retry/rollback a mutation and reconcile a timeout after the external
  side effect occurred;
- revoke/rotate provider credentials and prove no secret persists in receipt;
- restart executor and adapter during work without duplicate asset or operation;
- run the same conformance against public reference and independently maintained
  downstream adapters.

## Hub and downstream delivery

Deploy the public executor at the reference installation with a site adapter
containing only protected bindings. An independent downstream supplies its own
read-only site adapter and protected inventory capture; synthetic capture is
acceptable for CI but not G24
certification. Remove all competing generic downstream inventory/executor code.

## Acceptance

- Public issues #27 and #28 close with real discovery/adoption/execution proof;
  #93 closes after its provider-neutral schema and topology path also passes.
- Every mutation has durable ownership, precondition, receipt, rollback and
  reconciliation behavior.
- Provider outage/rate limit cannot block unrelated tenants or system recovery.
- G07-G27 may consume only this public executor contract.
