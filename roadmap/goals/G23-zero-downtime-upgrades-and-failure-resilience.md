# G23 — Zero-downtime upgrades and failure resilience

## Outcome

Run the integrated campaign proving the single-region platform and every product
survive supported failures and upgrades with zero release downtime, no data loss,
no duplicate operations and no invalid billing. Individual HA/upgrade behavior
was implemented earlier; this goal proves the system as a whole.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Finalize release/version policy, N/N-1 matrix, OCS candidate compatibility,
  deprecation, expand/migrate/contract and rollback boundaries.
- Consolidate progressive rolling/blue-green traffic shift, automated acceptance,
  abort and rollback across core and independently versioned products.
- Audit all production claims for replica/quorum/topology/headroom and remediate
  any remaining single-instance dependency.
- Run pre-upgrade backup/restore validation and continuous measurement using
  actual signed adjacent prereleases, never two workspace builds.
- Execute one-server-loss, control-plane API, PostgreSQL, OpenBao, network,
  storage, VM, managed Kubernetes, object, backup and connector drills.
- Keep continuous login/session refresh, IAM decisions, usage ingest, rating,
  balanced ledger and invoice-read probes running through replica loss and the
  signed N-1-to-N release.
- Lose the management plane while existing data planes run, then reconcile all
  accepted operations, usage and audit on recovery.

## Required journeys

1. Install signed G22 prerelease, create representative resources/usage and
   upgrade core/products to signed G23 candidate under one-second probes.
2. Fail a canary and prove automatic rollback before wider exposure.
3. Exercise rollback before and restore/recovery after the documented irreversible
   migration boundary.
4. Remove/reboot one eligible server and prove direct IPv4/IPv6, portal/API,
   PostgreSQL, VM, product, usage and audit continuity plus cleanup.
5. Fail secret, database, storage, network and remote connector components in
   separate bounded drills.
6. Verify cumulative G00-G22 journeys after every recovery.

## Hub and downstream delivery

Run the complete campaign on the exact maintained-reference revision with approved
mutation tuples and dedicated data. Generic defects return to OSS. An independent
downstream runs the full non-destructive campaign and prepares site mutation
inputs; its real failure campaign completes in G24.

## Acceptance

- Zero-downtime, RPO/RTO and soak definitions in the measurement contract pass.
- Tasks 21-24 are freshly re-proved against final product paths.
- Issues #81, #82, #33 and #84 close only after their observer, recovery,
  one-server-loss and supported-version criteria pass this integrated campaign.
- CDN/DNS fallback never substitutes for a required direct-origin proof.
- Rollback, cleanup, drift and cumulative regression are green.
