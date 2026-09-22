# Release Contract

This directory owns the public release and BOM compatibility boundary for
CloudRING.

The contract is not a production-grade readiness claim. It describes which release
records, BOM rows, evidence gates, stale states, and blocked states a downstream
release reviewer must evaluate before any live promotion claim is considered.

Public release records must keep `claims.liveProductionReady` set to `false`
unless a downstream repository attaches scoped live evidence outside this public
core tree. Blocked, absent, stale, synthetic, or fixture evidence does not
convert a release record into a live claim.

## Files

- `release-bom-contract.json` defines the public release/BOM fields and gate
  behavior.

## Non-Claims

This directory does not include live infrastructure evidence, provider details,
tenant data, private endpoints, credentials, or deployment receipts. It also
makes no GA release claim.
