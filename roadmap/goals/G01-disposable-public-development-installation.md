# G01 — Disposable public development installation

## Outcome

From a fresh public clone, a contributor or product team can create and destroy a
real isolated CloudRING development environment with one supported command. It is
safe, observable and useful for integration testing, but is unmistakably not a
production topology.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified in an isolated scope beside
`https://hub.cloudring.org`.

## Scope

- Publish pinned prerequisites and a reproducible local/CI profile using a
  supported disposable Kubernetes environment.
- Implement `validate`, `create`, `status`, `diagnose`, `reset` and `destroy` with
  deterministic plans, idempotency, timeouts, cancellation and cleanup receipts.
- Install the real management-plane binaries, schemas, migrations, API and portal
  shell; do not replace them with fake backends.
- Supply development-only identity, storage and secret bindings that are clearly
  namespaced, non-production and impossible to select in a production profile.
- Run the same public APIs and extension points intended for production.
- Generate privacy-safe diagnostics and teardown all owned resources, volumes,
  credentials, processes and network artifacts.

## Required journeys

1. Start on a clean machine/repository, validate prerequisites, create the
   environment and observe the empty-provider readiness shell.
2. Re-run create and prove no unintended change.
3. Restart platform processes and recover durable development state.
4. Execute positive and negative API/CLI smoke tests with the bounded development
   operator identity.
5. Destroy, verify zero owned residue, then recreate from the same inputs.
6. Follow the public tutorial from an independently controlled clean-room CI job
   using no non-public checkout or unpublished local module.

## Hub and downstream delivery

Run the disposable profile in a dedicated namespace/cell and non-customer
hostname beside the hub; it must have no ownership over current production
resources. Both downstreams pin the public release and run create/status/destroy
in CI. No development credential or data is copied into production evidence.

## Acceptance

- The complete journey meets the installation/DX measurement profile.
- Production validation rejects every development-only shortcut.
- Public issue #32 is partially satisfied for development; production closure
  waits for G02.
- The signed G01 prerelease is reproducible and its destroy receipt is green.

## Non-goals

HA, customer identities and sellable products are not claimed. The environment is
a real integration system, not production evidence.
