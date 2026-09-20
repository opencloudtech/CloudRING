# Isolated etcd recovery worker contract

The public worker verifies and restores one etcd snapshot without contacting a
live etcd member or starting an etcd server. It accepts either an exact local
archive or one bounded, exact-version HTTPS fetch from an S3-compatible object
store; status and restore processing then run entirely offline.

The stable public wire IDs are:

- `cloudring.etcd-recovery.request/v1`;
- `cloudring.etcd-recovery.receipt/v1`;
- `cloudring.etcd-recovery.input-secret-projection/v1`;
- `cloudring.etcd-recovery.image-identity/v1`.

The request and credentials use a strict Kubernetes atomic-writer projection
reader. It accepts one stable in-root `..data` generation, exact allowlisted key
links, root- or process-owned bounded regular targets, and no extra keys,
escapes, hard links, writable group/other modes, or path changes.
`inputSecretSha256` is specifically the SHA-256 of the canonical
`input-secret-projection/v1` document: namespace, Secret name, `request.json`
key, fixed mount path, mode `0440`, `optional=false`, and `readOnly=true`. It is
not a digest of `request.json` or Secret data. The outer adapter must separately
bind the observed Secret UID/resourceVersion and Pod volume projection.

A local archive must be a stable process-owned `0400` or `0600` single-link
file, and all raw object-store fields must be empty. In `s3` mode, the worker
reads the endpoint, region, bucket and exact object version only from the
protected request, reads the explicit `access-key-id` and `secret-access-key`
projected files (plus optional `session-token`), and performs one signed HTTPS
GET with system CA validation, no proxy and no redirect. Raw endpoint, bucket,
object key/version and credentials never appear in tool arguments, environment,
stdout, stderr or receipts.

`etcdutl` 3.6.14 is content-pinned to
`2b7fea46e31fda1989168fbd8f7ec73f5839155f4b1af7bab274950e337e996d`
before execution. This executable is rebuilt from the unchanged official source
with Go 1.26.8 and retained symbols using the [release build procedure](../../docs/releasing.md);
its source and build identity are retained as `etcdutl-source.json`.
Source `hashkv` runs only against a verified disposable
private copy, because upstream `hashkv` can mutate bbolt metadata. The restored
private database is hashed, reopened, digested and inspected again. Success
requires exact equality of the semantic KV hash, hash revision, compact
revision, snapshot revision, key count and etcd version. The receipt binds
digests of both status and KV-hash documents.

The worker writes one bounded owner-only canonical terminal receipt to
`/work/output/receipt.json`; stdout remains empty. Verified, failed, cancelled
and timeout receipts contain stable status/reason/stage fields. Success is
returned only after the private restore workspace is removed and absence is
verified. Request work is capped at 1800 seconds, cleanup at 30 seconds, and the
template Job deadline is 1860 seconds so cleanup and the terminal receipt retain
a bounded margin. `memberHealthVerified` is always false because no live member
is contacted; `offlineMemberDatabaseVerified` records only the offline database
fact.

Downstream Kubernetes workloads must additionally set:

- a digest-pinned published image;
- non-root UID/GID with a read-only root filesystem;
- `automountServiceAccountToken: false`;
- no host network, PID, IPC, privilege escalation, or added capabilities;
- a bounded writable `emptyDir` only for `/work`;
- no Service and no route to etcd client or peer ports;
- exact object-store egress. The checked-in TEST-NET CIDR is deliberately
  non-runnable and must be replaced, never widened to unrestricted HTTPS.

## Downstream handoff

Enterprise orchestration and evidence may retain a Goal 01 iteration label, but
must consume the stable `cloudring.etcd-recovery.*` public wire IDs above
without translating them into goal-scoped schemas.

These source contracts do not prove that a downstream object was acquired,
that its identity was authorized, or that a live cluster is recoverable. The
outer adapter must bind the receipt and observed Pod `imageID` through accepted
release identity, alongside the exact Job/CronJob template digest,
execution-profile digest, request Secret identity digest and accepted cluster
identity. The worker binds those reviewed values but cannot self-attest its OCI
runtime identity. Use
`ParseCanonicalReceipt`, `EndpointSHA256`, and `ObjectReferenceSHA256` rather
than duplicating public parsing or projection semantics.

For an OCI index, equality is resolved through the accepted image-identity
document: `Receipt.WorkerImageDigest` binds `imageDigest`, while the observed
Linux AMD64 Pod `imageID` binds `imageSubjectDigest`. Do not compare those two
different digest levels directly.

The protected release workflow emits a canonical image-identity document that
binds the source commit, published image/index and Linux AMD64 subject digests,
worker and `etcdutl` hashes, base image, Containerfile, component inventory and
real image SBOM. That release evidence is necessary for downstream pinning; it
does not establish live recovery readiness.
