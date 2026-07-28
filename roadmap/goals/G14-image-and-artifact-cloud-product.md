# G14 — Image and artifact cloud product

## Outcome

Deliver secure machine-image and OCI-artifact products through OCS. Tenants can
import, push, validate, version, share, replicate, cache and delete VM images,
container images and supply-chain artifacts for later compute and application
workloads. The earlier G07/G08 platform-package path remains independently
bootstrappable and does not depend on this tenant product.

All reusable implementation must merge into public OSS and the exact accepted
change must be deployed and live-verified at `https://hub.cloudring.org`.

## Scope

- Define VM image, artifact repository, manifest/blob, version/tag/digest, source,
  format, architecture, boot compatibility, visibility, licence and lifecycle
  contracts.
- Support resumable upload/import from approved sources, checksum/digest,
  conversion where justified, malware/vulnerability scanning, signature and SBOM.
- Implement OCI Distribution-compatible push, pull, copy and deletion for
  container images and arbitrary artifacts, with referrers/attestations and no
  mutable-tag ambiguity in accepted operations.
- Implement quarantine, moderation, tenant/private/shared/public visibility,
  explicit sharing and revocation.
- Store immutable content by digest with garbage collection, reference counting,
  retention and recoverable deletion.
- Implement regional cache/replication with integrity, bounded concurrency,
  backpressure and no duplicate billing.
- Meter stored bytes, transfer and transformation; enforce quota/capacity and
  cost preview.
- Provide API, CLI, portal extension, progress Operations, audit, observability,
  support, backup/restore and upgrade/rollback.

## Required journeys

- upload and remote import a valid VM image, validate/scan/sign, publish privately,
  share, revoke and delete;
- push/pull/copy a multi-architecture OCI artifact by digest, attach verified SBOM
  and provenance, move a tag without changing an accepted digest, then garbage
  collect only unreferenced content;
- reject corrupt, unsupported, malicious, unsigned-when-required and
  unauthorized images before use;
- interrupt large upload/conversion, resume idempotently and verify final digest;
- cache to the reference cell, evict and rehydrate without changing image ID;
- restore image metadata and content references after backup;
- prove cross-tenant denial and correct usage/cost.

## Hub and downstream delivery

Deploy the signed OSS image/artifact product at the reference installation, bind
only its site storage locations downstream and complete both live lifecycles with
test content. An independent downstream runs format, distribution, prerequisite
and clean-room conformance without non-public reference assets.

## Acceptance

- No static catalog entry or local fixture is presented as an available image.
- The G14-owned public boot-compatibility harness proves immutable provenance and
  supported architecture/firmware/format combinations without depending on G15.
- Tenant OCI artifacts remain portable to conformant registries and are not
  coupled to the CloudRING management cluster.
- Scanning and conversion failures cannot expose partial content.
- Retention, legal/licence metadata and deletion behavior are documented and
  enforced.
