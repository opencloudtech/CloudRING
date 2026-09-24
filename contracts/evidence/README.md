# Evidence Contract

This directory owns the public evidence freshness and blocked-state boundary for
CloudRING.

The contract is not a production-grade readiness claim. It defines how a release
reviewer treats accepted, stale, blocked, absent, synthetic, and redacted
evidence before any downstream live promotion claim is evaluated.

Public evidence contracts must keep `liveProductionReady` set to `false`.
Downstream repositories may attach scoped evidence records, but those records
must remain outside CloudRING tree when they contain live deployment
details.

## Files

- `evidence-freshness-contract.json` defines evidence classes, freshness windows,
  blocked states, cleanup expectations, and non-claim behavior.

## Non-Claims

This directory does not include live evidence files, provider inventory,
customer data, credentials, operational transcripts, or private deployment
details. Stale, blocked, or missing evidence blocks promotion claims.
