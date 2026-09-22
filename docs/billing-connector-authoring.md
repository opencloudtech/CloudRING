# Billing Connector Authoring

Billing connectors translate service usage into OCSv3 (Open Cloud Standard 3)
meters, cost meters, entitlement links, idempotency keys, replay behavior, and
dispute-ready evidence. CloudRING validates the billing connector without
knowing the service billing backend.

## Required Surfaces

Each billing connector declares:

- metadata owner and version;
- usage meters with stable names and units;
- cost meters with currency, unit price label, meter ref, and evidence ref;
- billing events with meter, idempotency key, entitlement ref, attribution, and
  replay policy.

The service connector must declare matching `usageMeters` and
`service.spec.billing.meters`, and `service.spec.billing.connectorRef` must match
the billing connector metadata name.

## Authoring Flow

1. Start from the service's user-visible usage events.
2. Define one stable usage meter per billable or reportable quantity.
3. Add cost meters only when evidence exists for the public rate-card label.
4. Use idempotency keys that deduplicate retries and replays.
5. Link entitlement refs to the catalog plan or subscription scope.
6. Validate with the service package:

```sh
go run ./cmd/ocsctl validate ./examples/synthetic-service-module/connector-package.json
```

## Boundary Rules

Do not embed payment credentials, customer records, settlement results, invoice
truth, or private billing-system schemas in CloudRING. The public connector
records the contract and evidence refs only. This document does not claim
production-grade readiness or billing settlement correctness.
