# OCSv3 Architecture

OCSv3 separates platform responsibilities from service-team implementation
details. This remains true whether a service ships in CloudRING or is maintained
in another repository.

```text
platform core
  reads module package
  mounts portal extension
  evaluates IAM/tenant access
  routes billing/support/evidence events
  reconciles lifecycle through declared Kubernetes and adapter contracts

service module
  owns CRDs/controllers
  owns service API
  owns billing connector
  owns support diagnostics
  owns portal microfrontend
  owns evidence receipts
```

The platform core depends on service metadata and APIs rather than importing a
service's internal packages. Provider integration lives behind adapter
interfaces. Reusable, source-safe adapters may ship in CloudRING; concrete
accounts, inventory, credentials, private endpoints, and installation overlays
stay in the downstream provider repository.

## Request Path

1. User selects a catalog plan.
2. IAM evaluates tenant, project, entitlement, and permission.
3. Portal renders the module extension if allowed.
4. The service controller reconciles a Kubernetes claim.
5. Billing events are emitted with idempotency keys.
6. Readiness and support evidence are recorded.
7. Denied, degraded, blocked, retryable, and ready states are visible.

No production-grade readiness claim is valid without current evidence.
