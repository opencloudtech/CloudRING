# G21 — External integration product

## Outcome

Deliver one complete real remote OCS product and prove its provider adapter can be
replaced without platform changes. This validates use cases such as external
cloud accounts, bare metal and licence entitlement without pretending three
templates are already products.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Select one open, legally usable, testable external system with real lifecycle,
  identity, rate limits, failures and usage. Record the choice in an ADR.
- Implement its complete product: discovery, explicit adoption, provision,
  suspend/hold, resize when applicable, deprovision, drift, cost/usage, support,
  upgrade and removal.
- Broker short-lived provider/tenant credentials and map external identifiers,
  errors and ambiguous outcomes through G06/G07 contracts and quota/capacity
  through G09.
- Implement remote interruption, store-and-forward events where needed,
  reconciliation before retry and adapter replacement.
- Provide complete API, CLI, agent automation, billing, quota/capacity, audit,
  observability, HA and recovery. A signed portal extension is optional; if the
  product declares one, it must pass the same moderation and sandbox contract.
- Publish non-product conformance templates for external-cloud account, bare-metal
  and licence integrations. They remain templates until separately implemented
  and must not appear in the catalog.

## Required journeys

- discover without mutation, explicitly adopt or provision, use, hold/resize and
  deprovision the real external resource;
- hit timeout/rate limit/outage after side effect and reconcile before retry;
- rotate/revoke broker credentials with no secret in package/receipt;
- ingest/correct external usage and trace invoice lineage;
- disconnect/reconnect, upgrade and replace the adapter while preserving product
  identity and accepted operations;
- reject unknown ownership, cross-tenant access and incompatible capability.

## Hub and downstream delivery

Run the real integration in an isolated hub tenant, then clean it. Implement a
second adapter in an independently controlled repository and pass replaceability
conformance without non-public reference access; it may target the same open test
system.

## Acceptance

- No external-vendor implementation exists in platform core.
- Unknown outcomes cannot produce duplicate assets or billing.
- At least two independent adapter implementations pass the same product
  lifecycle and upgrade suite.
- Bare-metal/licence/account templates carry explicit non-product labels.
