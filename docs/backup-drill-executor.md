# Goal01 backup drill executor

`cloudring-backup drill` is the provider-neutral transaction engine for one
reviewed backup/restore proof operation. It does not contain an OVH, Velero, or
Kubernetes implementation. Those mutations live behind a small external
adapter protocol so this public engine can enforce approval, identity,
journaling, recovery, cleanup, and proof invariants independently.

## Artifacts and trust boundary

The versioned plan binds the operation, proof, and installation IDs; accepted
public and downstream Git SHAs; cluster identity digest; exact
BackupStorageLocation UID, observed generation, and effective config digest; object-store prefix,
minimum retention of at least 30 days, and governance/compliance object-lock
mode; five source baselines; tool and adapter executable digests; one Backup,
four Restore identities/scopes, and five explicit source-to-isolated namespace
mappings; etcd sandbox; cleanup targets with identity preconditions; issuance, expiry, nonce,
and downstream aggregate-proof path token.

The storage-location generation is audit context from plan issuance. It is not
a universal desired-state fence: provider CRDs without a status subresource can
legitimately advance generation during status validation while leaving the
effective configuration unchanged. Adapters therefore prove live continuity
with the exact UID plus canonical effective-configuration digest; a changed UID
or configuration fails closed.

All external JSON is size-bounded and rejects malformed input, duplicate keys,
unknown fields, trailing documents, and unsafe depth. The schemas are in
`contracts/backup-drill`. Plans, approvals, adapter requests/responses, journal
entries, and receipts have independent schema versions and SHA-256 bindings.

The adapter executable is resolved, copied, and SHA-256 pinned once per CLI
operation before its identity is compared with the plan. It receives one
request on stdin, the literal `drill` argument, bounded stdout/stderr, and a
deadline. The CLI requires a pipe-backed kubeconfig descriptor. Each adapter
phase receives a fresh anonymous replay pipe referenced only as
`KUBECONFIG=/dev/fd/<n>`; credential bytes never appear in the plan, argv, or
environment. The environment is rebuilt from the fixed locale seed plus the
replay's fail-closed prompt and descriptor variables, so ambient cloud or home
credentials are not inherited. The engine never invokes a shell and rejects
credential-like response material. The adapter may consume its child
kubeconfig descriptor into its own in-memory replay for multiple cluster calls.
The running `cloudring-backup` executable is independently content-pinned and
must match the plan's exact tool digest before any approval or mutation.

## Commands

The plan is the only normal JSON input. Approval, journal, and receipt paths
must be in a trusted non-group-writable directory and are created owner-only.
Existing outputs are never overwritten.

```sh
cloudring-backup drill preflight \
  --plan /protected/goal01-plan.json \
  --adapter /opt/cloudring/bin/goal01-adapter \
  --kubeconfig-fd 3 \
  --approval /protected/goal01-approval.json
```

Preflight invokes only the declared adapter `preflight` operation. A response
that reports a mutation is rejected. The approval prints and records the exact
fresh tuple:

```text
goal01-backup-restore@<issuedUnix>@<acceptedDownstreamSHA>@<runNonceSHA256>@<approvalScopeSHA256>@<preflightBindingSHA256>
```

`preflightBindingSHA256` canonically binds the live adapter response digest,
evidence reference and digest, pinned adapter digest, and approval scope. A
different or replayed preflight result therefore produces a different tuple.

Apply requires that exact tuple as an explicit confirmation:

```sh
cloudring-backup drill apply \
  --plan /protected/goal01-plan.json \
  --approval /protected/goal01-approval.json \
  --adapter /opt/cloudring/bin/goal01-adapter \
  --kubeconfig-fd 3 \
  --journal /protected/goal01-journal.jsonl \
  --receipt /protected/goal01-receipt.json \
  --confirm 'goal01-backup-restore@...'
```

The engine creates and synchronizes `approval-consumed`, then synchronizes the
engine-owned `mutation-started` phase before the first adapter mutation. It
then enforces this exact order:

1. `etcd-offcell-complete`
2. `velero-backup-complete`
3. `restore-watch-create-observe-complete`
4. `etcd-sandbox-restored`
5. `restore-validation-complete`
6. `cleanup-ready`
7. `isolated-targets-deleted`
8. `residual-sweep-1`
9. `residual-sweep-2`
10. `proof-assembled`
11. engine-owned `completed`

The combined restore phase is one long-running adapter process. It establishes
the LIST/WATCH observer, proves it ready, creates all four Restore objects only
after readiness, and remains alive until the required DataUploadResult
observations are durably captured. A separate ready process cannot exit before
Restore creation, so secure execution containment cannot introduce a watch gap.
Mapping cardinality is fixed at `1,1,2,1`: the Namespace Restore must map both
`platform-system` and `flux-system` to distinct isolated destinations. All five
destinations have plan-bound observation scope and exact cleanup targets.

Each adapter request is idempotently identified from the operation, plan,
approval, phase, and prior journal head. Every successful response is stored in
the append-only, per-entry hash-chained journal before the next phase. Recovery
recomputes every prior request and rejects gaps, reorder, duplicate phases,
tampering, changed input, conflicting response digests, different adapter
identity, and rolled-back runs:

```sh
cloudring-backup drill recover \
  --plan /protected/goal01-plan.json \
  --approval /protected/goal01-approval.json \
  --adapter /opt/cloudring/bin/goal01-adapter \
  --kubeconfig-fd 3 \
  --journal /protected/goal01-journal.jsonl \
  --receipt /protected/recovered-receipt.json \
  --confirm 'goal01-backup-restore@...'
```

Rollback first asks the adapter to safe-stop new mutation. It then sends only
the exact plan cleanup targets and identity preconditions while requiring the
adapter to retain `Backup`, `DataUpload`, `ObjectStoreRecoveryPoint`, and
proof-scoped `RestoreAuditCR` recovery records:

```sh
cloudring-backup drill rollback \
  --plan /protected/goal01-plan.json \
  --approval /protected/goal01-approval.json \
  --adapter /opt/cloudring/bin/goal01-adapter \
  --kubeconfig-fd 3 \
  --journal /protected/goal01-journal.jsonl \
  --confirm 'goal01-backup-restore@...'
```

Safe-stop, cleanup request, and `rolled-back` or `rollback-failed` are durable
journal outcomes. Failed cleanup never produces `completed` or a receipt.
Recover and rollback may use the consumed approval after expiry, but still
require the operator to supply its exact preflight-bound tuple. The engine holds
one exclusive journal-inode lock across reload, adapter actions, append/fsync,
and final receipt construction, preventing recovery/rollback forks.
Once any rollback phase is durable, `recover` rejects the run and cannot return
to apply mutations. Re-running `rollback` resumes from a durable safe-stop by
issuing only the exact idempotent cleanup request, or from a durable cleanup
response by appending its deterministic terminal outcome without reissuing the
mutation. Repeating an already successful rollback is an idempotent success.

## Receipt gate

A completed receipt cannot be derived from plan data. It requires the stored
`proof-assembled` adapter response and all thirteen verified journal phases.
It contains exactly `Etcd`, `VirtualMachineClaim`, `Volume`, `Namespace`, and
`KubernetesClusterClaim`, with restored checksums equal to the exact five
plan-bound source baseline digests and per-target evidence references and
digests. Receipt validation first revalidates the complete journal and requires
every receipt field to equal the stored `proof-assembled` response. It also
binds isolation evidence, cleanup
evidence, the object-lock delete-denial receipt digest, the journal head, the
adapter proof-response digest, and the aggregate proof artifact digest/path
token consumed by the downstream Enterprise assembler.

## Adapter implementation gap

The public repository includes a deterministic test adapter that proves the
portable stdin/stdout protocol, executable pinning, retry stability, partial
responses, crashes, credential-output rejection, and rollback failures. It is
not a live adapter. The downstream release must still implement and verify the
concrete protected-cluster/Velero/etcd/object-store adapter, including its
credential delivery, real mutation idempotency, object-lock denial evidence,
and live cleanup precondition behavior. Until that adapter and live evidence
exist, this engine is executable infrastructure but not a claim that a live
Goal01 drill passed.
