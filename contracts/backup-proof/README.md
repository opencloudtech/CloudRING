# Backup and Restore Proof Contracts

This directory defines the public, provider-neutral contract used to collect an
unsigned proof for one Velero 1.18.2 CSI data-mover volume restore.

- `baseline-request.schema.json` identifies the source PVC before the Restore
  exists.
- `collection-request.schema.json` identifies the completed Restore, source
  and target PVCs, archived DataUpload, and fresh official Velero
  ServerStatusRequest selected for the drill, plus the source-safe digest of a
  fresh cleanup run nonce.
- `data-upload-result-observation-request.schema.json` identifies the exact
  short-lived Velero result that must be watched before the Restore exists.
- `data-upload-result-observation-ready.schema.json` defines the request-bound
  barrier after the initial empty LIST fence and before Restore creation.
- `data-upload-result-observation.schema.json` defines the private captured
  `ADDED` event consumed by the terminal collector. Velero deletes this
  ConfigMap before publishing terminal Restore status.
- `adapter-protocol.schema.json` defines the stdin/stdout protocol for an
  independent data probe and a read-only provider artifact observer.
- `adapter-digest-conformance-vectors.json` publishes language-neutral
  canonical request bytes and SHA-256 vectors for both adapter request kinds.
- `cleanup-ready.schema.json` defines the source-safe, run-bound barrier that
  permits the downstream workflow to start isolated-restore cleanup.
- `restore-proof.schema.json` describes the source-safe receipt emitted only
  after content validation and cleanup observations pass.

Runtime validation in `pkg/backup/restoreproof` is authoritative. JSON Schema
alone cannot validate cross-object identity, canonical hashes, timestamps,
pagination fences, or the minimum interval between provider observations.

The observation workflow uses an exact initial LIST resourceVersion followed
by WATCH without a relist gap. It fails closed on expired resourceVersions,
malformed events, replacement, ambiguity, or a Restore that already exists.

The cleanup-ready marker authorizes only a downstream cleanup that deletes the
exact restored PVC, PV, and DataDownload with both Kubernetes UID and resourceVersion
preconditions and prevents their re-creation until a valid receipt exists or
the run is abandoned. Polling can reject replacements it observes, but cannot
prove that a short-lived replacement never existed between observations. The
marker deliberately omits raw UIDs and resourceVersions; the downstream
workflow must retain them in protected runtime state. The observed result
ConfigMap is excluded from downstream deletion because Velero owns and removes
it; the collector separately proves its exact post-Restore absence.

The receipt binds the source PVC to its exact source PV, rejects a source and
restored PV that share an identity or CSI handle, and requires the source
provider handle to remain present after both restored-handle absence
observations. This is a single-volume continuity control, not a full
application-consistency or tenant-isolation proof.

The provider adapter receives a raw provider handle only on stdin. It must not
write that handle, credentials, endpoints, response bodies, or tenant data to
stdout or stderr. Its response contains only an implementation/version pair,
presence status, timestamp, the unique request digest, pinned executable
digest, and hashes of separately protected runtime evidence. The data probe
follows the same rule for workload content.

Adapter protocol v2 is self-describing: every request carries
`requestDigestCanonicalization`. `requestSha256` is the SHA-256 of
`cloudring.restore-proof.adapter-canonical-json/v1`. Implementations must sort
object keys lexicographically at every depth, emit UTF-8 JSON without
insignificant whitespace, escape quotation mark and reverse solidus, use the
standard short escapes for backspace/tab/newline/form-feed/carriage-return,
encode other U+0000 through U+001F values as lowercase `\u00xx`, and emit all
other valid Unicode scalar values directly as UTF-8. This protocol version has
no numeric request fields. The repository-owned conformance vectors are
normative and deliberately include Unicode plus characters that Go's default
JSON encoder HTML-escapes.

These contracts do not claim production-grade readiness. They also do not define
credentials, object-store configuration, or a deployment topology. Live
receipts and baselines are deployment-private artifacts and must not be
committed here.
