# PostgreSQL HA profile

This provider-neutral profile supplies a three-instance PostgreSQL 18 cluster
for durable CloudRING control-plane and business state. CloudNativePG owns
election and failover; the database pods use hard hostname anti-affinity,
quorum synchronous replication, fail-closed durability, TLS, SCRAM, separate
replicated PGDATA and WAL volumes, and a PodDisruptionBudget.

The `controllers` stage pins the CloudNativePG chart, operator image, webhook
failure policy, security context, and two controller replicas. Its source
HelmRelease is suspended. A downstream Flux root must activate it only after
the CRDs, cert-manager, target Kubernetes version, and two-node controller
placement have been checked.

The chart is reconciled from the official
`oci://ghcr.io/cloudnative-pg/charts/cloudnative-pg` OCI artifact at manifest
digest
`sha256:209c588b902982bf283a0073db83edd422d9710a2c8a670fe57c0329abe789a4`.
The reviewed chart content and provenance layer digests are recorded in
[`../runtime-chart-supply-chain.json`](../runtime-chart-supply-chain.json).
The operator remains image-pinned to CloudNativePG `1.30.0`. A mutable Helm
repository, tag-only chart selection, or documentary checksum annotation is
not an accepted source contract.

The same suspended controller stage installs the official Barman Cloud CNPG-I
plugin chart `0.7.0` / application `v0.13.0` from
`oci://ghcr.io/cloudnative-pg/charts/plugin-barman-cloud` at manifest digest
`sha256:5d31605cad886f93abb7cd9884170d74ece913fe8b95c74b127ec5e8bcd2b2b6`.
Both the manager and injected instance sidecar use immutable multi-platform
image digests recorded in the shared supply-chain manifest. The plugin runs
two leader-election replicas with hard topology spreading and a disruption
budget. cert-manager must already be Ready because the official plugin uses
mutual TLS for its CNPG-I endpoint. Digest pins prove source identity only;
they do not prove the plugin, certificates, WAL archiver, or backups are live.

The Helm values set both `serviceAccount.create=false` and `rbac.create=false`.
The profile supplies a dedicated `cloudring-cnpg-barman-cloud` ServiceAccount
and the exact reviewed upstream v0.13.0 manager ClusterRole and binding instead
of accepting chart-generated manager RBAC. That manager grant is nevertheless
cluster-wide: upstream v0.13.0 has no namespace watch restriction, so this is a
reviewed residual limitation rather than a least-privilege claim. The chart
also renders its namespaced `cnpg-system` leader-election Role and RoleBinding
unconditionally; disabling `rbac.create` does not remove that separate grant
over ConfigMaps, Leases, and Events. Review both residuals on every chart
upgrade.

The `runtime` stage is an explicit compact-cell reference. It consumes the
public `longhorn-replicated` StorageClass and `longhorn-retain`
VolumeSnapshotClass. Sites using another CSI implementation must patch both
names to durable equivalents that have already passed the CloudRING storage
and restore gates. Do not reduce three replicas, hard host separation,
synchronous durability, failover quorum, TLS, or the retained snapshot policy.

Before applying the runtime stage, the installation must create two
`kubernetes.io/basic-auth` Secrets in `cloudring-database` through the approved
runtime secret manager. Both must carry `cnpg.io/reload: "true"` and contain
only `username` and `password`:

- `cloudring-postgres-owner` uses username `cloudring_owner`. This database and
  schema owner is projected only into the one-shot migration workload.
- `cloudring-postgres-app` uses username `cloudring_app`. This managed role is
  the only identity projected into steady-state application workloads.

Never put either Secret, a DSN, or rendered secret material in Git, command
arguments, logs, or evidence. After the migration gate, remove the migration
workload and its owner-Secret projection; do not expose owner credentials to
application replicas. Applications must use the generated read-write service
with `sslmode=verify-full` and the operator-generated CA bundle. Same-namespace
clients require the pod label `cloudring.org/postgresql-client: "true"`.
Cross-namespace clients require both that pod label and the namespace label
`cloudring.org/postgresql-client-namespace: "true"`; neither label alone grants
access. A downstream may replace this with an equally narrow NetworkPolicy.

The included six-hour online VolumeSnapshot schedule remains a local recovery
layer. It is intentionally preserved alongside the off-cell layer and is not
an off-cell disaster-recovery claim.

The runtime stage delegates continuous WAL archival to the official
`barman-cloud.cloudnative-pg.io` plugin and schedules a daily online base backup
from a preferred standby. The namespaced `ObjectStore` has a 30-day recovery
window and requires a downstream bucket with at least 30 days of governance or
compliance Object Lock. It uses a provider-neutral S3 URI in source. Before
activation, each site must patch that URI to a dedicated bucket and prefix and,
for a non-AWS S3-compatible implementation, add its reviewed HTTPS endpoint
and CA reference. The bucket must be in a failure domain distinct from the
Kubernetes cell, enable versioning and encryption, and deny a controlled
deletion while retention is active. A source render or a successful upload is
not evidence of these properties.

No credential value is stored in this profile. The production `ExternalSecret`
projects only `ACCESS_KEY_ID` and `ACCESS_SECRET_KEY` from the platform runtime
secret manager. A site may replace access keys with an equally reviewed
workload-identity mechanism, but it must not put a credential, session token,
endpoint credential, or rendered Secret in Git. Rotation and revocation remain
live gates.

The production and recovery projections use separate namespaced `SecretStore`
objects, never a shared `ClusterSecretStore`. Before activation, OpenBao must
provide the exact Kubernetes auth mounts and roles declared by each store,
bound only to its named reader ServiceAccount and `openbao` audience. Its
policies must limit the production role to the off-cell write credential path
and the recovery role to the recovery S3 and recovery-database paths. Each
namespace must also receive the trusted `openbao-client-ca` ConfigMap with the
reviewed `ca.crt`; the source reference does not prove that the role, policy,
CA, token exchange, secret sync, rotation, or revocation works live.

The separate `recovery` stage is a drill template, never part of the normal
application route. It bootstraps a new one-instance Cluster from the off-cell
base backup and WAL chain in `cloudring-database-recovery`, uses a distinct
read-only object-store credential plus a separate recovery-only database owner
credential, and reuses neither production credential. It has no production
client selector and permits database ingress only from an explicitly labelled
recovery validator in the same namespace; the only other ingress is the
operator's TCP/8000 management port from `cnpg-system`. Do not expose TCP/9090
on a recovery database pod: that is the plugin manager Service port in
`cnpg-system`, not a recovery-pod ingress requirement. Do not add an Ingress,
Gateway, HTTPRoute, production client label, or production application workload
to this namespace. Apply the stage only for a reviewed drill; after validation
delete the whole namespace using the transaction's recorded UID precondition.
Physical database recovery never restores Kubernetes Secrets. The namespaced
SecretStore must project both recovery-only Secrets before the recovery Cluster
is created, and cleanup must remove those projections with the namespace.

Recovery egress is fail-closed in source. `192.0.2.1/32` and `192.0.2.2/32`
are TEST-NET documentation bindings, not deployable defaults. A site must
replace them with the exact private Kubernetes API endpoint CIDR and port and
the exact dedicated off-cell object-store endpoint CIDR and TLS port; changing
only the address while retaining an incorrect port is not sufficient. These
policies use raw `ipBlock` peers. Service translation and CNI DNAT ordering can
make the address observed by NetworkPolicy differ from the configured Service
or VIP, so the site must bind the effective destination CIDRs and prove the
result with its actual CNI. Until then, recovery is intentionally unable to
reach either endpoint.

[`recovery/evidence.schema.json`](recovery/evidence.schema.json) defines the
sanitized **v2** pass contract. Historical v1 receipts remain historical and
cannot qualify this contract. V2 retains the completed non-empty base backup,
continuous WAL, distinct off-cell destination, 30-day retention and Object Lock
with denied control deletion, one Ready recovered instance, zero production
routes, positive matching combined row/byte counts, and two cleanup sweeps
separated by at least 30 seconds. It also requires these concrete results:

- Capture all protected logical classes and the validated ownership/ACL catalog
  in one repeatable-read, read-only snapshot with no assigned XID. The snapshot
  must have equal bounds and no active XIDs. On the same bound primary, create a
  unique marker, observe no assigned XID before and after it, then allocate the
  fresh marker transaction's first XID and confirm commit in the specified
  order. That allocation must equal the snapshot bound. Hashes supplement these
  facts; matching hashes alone do not qualify the interval.
- Verify archival of the exact marker record's WAL segment, select a base backup
  that precedes the marker, and prove that physical recovery reached the exact
  marker and LSN. Restore-point LSNs identify the record end, so segment selection
  uses the preceding byte at an exact WAL boundary.
- Bind the expected recovery principal, policy and policy revision, Secret and
  Secret version, destination, and read scope to independent readback before
  projection. The reader must differ from the backup writer. Effective policy
  must permit the required reads and deny writes, deletes, administration, and
  access outside that scope. Read the selected base backup and exact marker WAL
  object, and project only the allowlisted recovery inputs. Object Lock denial
  alone does not establish a read-only principal.
- Validate source and recovered ownership, role, ACL, migration, table, column,
  constraint, and index contracts and compare their canonical digests. Use a
  real application connection for six successful document/audit operations and
  eight specific SQLSTATE `42501` denials. Every probe must identify the actual
  application role. Roll back, verify zero synthetic rows, and compare logical
  and catalog digests again before cleanup.
- Retain exactly `portal-state`, `orders`, `support-tickets`, `audit-events`, and
  `postgresql-cnpg`, in that order. Each class must match its recovered digest,
  byte count, and row count. The combined class must match the existing checksum
  fields and the sum of the three detail-class row counts. Empty individual
  detail classes are supported; the existing positive combined-count gate is
  retained.

The public `pkg/backup/cnpgrecovery.Evidence` and its exported nested types allow
an installation adapter to construct this receipt without maintaining another
schema model. `VerifyEvidence` validates supplied v2 facts; use
`VerifyEvidenceForRevision` to bind them to the accepted public-core commit.
Both reject missing, duplicate, unknown, malformed, downgraded, or mutually
inconsistent facts, including absent denial and zero-count fields. JSON null is
accepted only for the two explicitly nullable timestamps. They enforce
capture, marker, archive, access, recovery, probe, cleanup, and collection
chronology. All operational identities are SHA-256 identities; receipts must
contain no raw XIDs, LSNs, marker names, endpoints, credential values, tenant
identifiers, database values, or raw command errors.

`recoveryAccess.expiresAt` bounds the independently verified access evidence and
must outlast recovered validation. `credentialExpiresAt` reports the provider
credential's actual expiry, or explicit JSON null only when independent checking
establishes that it does not expire. `expiryChecked` is always required.
The allow/deny operation names, exact object shape, and ordered class/probe lists
are shown in the [synthetic v2 fixture](../../../pkg/backup/cnpgrecovery/testdata/synthetic-v2-evidence.json).
That fixture is test data and contains no completed live recovery claim.

Source-schema validation checks the complete v2 shape and constraints. Receipt
validation checks only supplied facts; neither replaces their independent live
collection, exact source/primary binding, off-cell continuity, recovered access
probes, or cleanup evidence. Until a real drill supplies them, the Goal01
`postgresql-cnpg` evidence class remains blocked.

The machine source verifier therefore reports the PostgreSQL profile as
`status: source-contract-ready` with `liveStatus: blocked` and explicit live
blockers. The aggregate manifest report may say
`status: source-contracts-verified`, but its `liveStatus` also remains
`blocked`. Both statuses are limited to source validation; all runtime and
production gates remain open.

Run schema migration before starting application replicas by passing the DSN
through an inherited anonymous pipe:

```text
cloudring-postgres-migrate --dsn-fd 3 \
  --owner-role cloudring_owner --application-role cloudring_app
```

The pipe must contain one self-contained URL-form DSN with its username and
password. The process rejects PostgreSQL environment fallbacks, passfiles,
service files, and client-key indirection; an explicitly referenced read-only
CA bundle remains supported through `sslrootcert`. It accepts neither a DSN
argument nor a DSN environment variable nor a regular file, and it never echoes
database configuration or underlying driver errors. It accepts a completely
absent schema or the exact recorded schema, owner, constraints, and grants;
partial or pre-existing drift fails closed. The application identity receives
only schema usage and document SELECT/INSERT/UPDATE/DELETE privileges and
cannot execute DDL in the CloudRING schema.
