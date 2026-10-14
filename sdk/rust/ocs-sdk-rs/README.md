# CloudRING Open Cloud Standard (OCS v3) Rust SDK (`ocs-sdk-rs`)

`ocs-sdk-rs` provides a self-contained, zero-dependency Rust implementation of the CloudRING Open Cloud Standard (`ocsv3.cloudring.io/v1alpha1`) domain types, state machines, idempotency guards, quota accounting, and conformance verification primitives.

## Design Properties

- **Zero external dependencies**: Built exclusively on the Rust standard library (`std`) for deterministic offline builds and zero transitive supply-chain advisories.
- **Memory safety enforced**: Compiles with `#![forbid(unsafe_code)]`.
- **Complete 9-service taxonomy**: Covers `compute`, `volume`, `network`, `kubernetes`, `object-storage`, `backup`, `access-control`, `support`, and `external-integration`.
- **Deterministic state & idempotency validation**: Enforces canonical identifier formatting, URN serialization, `Pending -> Running -> Succeeded/Failed/Cancelled` operation state transitions, and idempotency key payload binding.
- **Explicit non-claims**: Conformance verification in this SDK validates structural contracts only and does not claim live production readiness.

## Verification

Run the unit test suite with a disposable target directory:

```bash
cargo test --manifest-path sdk/rust/ocs-sdk-rs/Cargo.toml --target-dir /tmp/ocs-sdk-rs-target
```
