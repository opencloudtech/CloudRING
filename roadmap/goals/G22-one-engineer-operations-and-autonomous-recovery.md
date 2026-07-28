# G22 — One-engineer operations and autonomous recovery

## Outcome

Consolidate the operability already built into G01-G21 and prove one trained
engineer can run the integrated platform in normal conditions within the measured
toil budget. This goal removes cross-product gaps; it is not the first time
individual components receive telemetry, backup or repair behavior.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Unify existing SLOs, dashboards, alerts, dependency health, GitOps drift,
  capacity, backup freshness, certificates, versions, incidents and risk in one
  operator console/CLI.
- Correlate OpenTelemetry signals, operations, audit and product state with
  cardinality/privacy budgets and no tenant-data leakage.
- Close diagnosis/repair gaps through explainable preflight, guided reversible
  repair, post-checks and privacy-safe support bundles.
- Consolidate certificate/credential rotation, restore rehearsal, storage scrub,
  node maintenance, capacity forecast and release qualification automation.
- Verify overload protection, maintenance modes and priority for system recovery
  across all products.
- Add SafePush runner-manager recovery, SNI/certificate rotation and signed-canary
  runbook with a measured recovery objective.
- Measure the operator profile and incident set in `MEASUREMENT_CONTRACT.md`, then
  remove recurring toil until targets pass.

## Required journeys

- diagnose/repair the full measurement incident set using shipped tooling/docs;
- rotate every supported credential/certificate without exposing secrets or
  losing accepted operations;
- perform node/product maintenance and verify cumulative user journeys;
- overload one tenant/product and preserve system/other-tenant SLOs;
- forecast/expand capacity through a reviewed plan;
- recover the isolated SafePush path from a clean manager bootstrap;
- complete 14-day healthy-state toil measurement and independent walkthrough.

## Hub and downstream delivery

Deploy the integrated operator experience to the hub and exercise bounded test
failures. An independent downstream uses the same diagnostics and automation and
supplies only alert routing, ownership and site bindings.

## Acceptance

- All critical alerts have owner, impact, runbook and resolution signal.
- Automation is scoped, approved, idempotent, audited and rollback-capable.
- Independent operator meets daily-toil, diagnostic and incident targets.
- Telemetry failure cannot stop the platform or create false green health.
