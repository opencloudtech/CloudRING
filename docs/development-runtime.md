# Public development runtime

`cloudring-server` serves the real CloudRING management API and portal shell with
PostgreSQL state. This is the serving component of delivery slice C02. It does
not, by itself, implement or qualify a complete developer installation.

The initial supported profile is `development`. The provider starts with a
durable empty registry and a single bounded development operator. No products,
customer tenants, orders, billing or healthy infrastructure are seeded. Product
APIs remain unavailable until their implementation is delivered. Production
profiles and development credentials in production configuration are rejected.

## Process and database boundaries

The installer generates a unique installation ID, per-installation CA, TLS
certificates, application/migration credentials and a 32-byte random development
operator key encoded as 64 lowercase hexadecimal characters. It retains these
inputs across retries; changing the installation ID or operator key against an
existing database fails closed. The original installation record is never
overwritten to make a retry succeed.

The database owner and application are distinct PostgreSQL login roles. Bootstrap
creates the roles and owns the database; `cloudring-server migrate` applies the
existing `transactionalstate` schema as its owner in a separate Job. Steady-state
serving receives only the application credential. Its startup checks the actual
login, database/schema ownership, effective role memberships and object
privileges. A privileged application role is rejected even if its name looks
correct. The serving process cannot run schema migrations.

Every database DSN is a complete protected PostgreSQL URL with the expected role,
password, explicit host/port/database, `sslmode=verify-full` and an absolute
`sslrootcert` path. Ambient environment/passfile authentication and an insecure
TLS switch are not supported. Secret file targets are regular files with no
world access or group write; Kubernetes projected Secret symlinks are supported.
Use mode `0400` or `0440` with the serving container's ownership/group. No secret
value is printed in a runtime error, health response or provider status.

## Configuration

The serving command is:

```sh
cloudring-server serve --config /run/cloudring/config.json
```

Its JSON configuration has these exact fields; all are required and unknown or
duplicate fields are rejected:

| Field | Meaning |
| --- | --- |
| `apiVersion` | `cloudring.org/v1alpha1` |
| `kind` | `CloudRINGDevelopmentRuntime` |
| `profile` | `development` |
| `installationID` | Stable lowercase installation ID, 3–63 characters |
| `publicOrigin` | Exact HTTPS origin used by clients, without path/query |
| `listenAddress` | IP/port or `:8443` inside the owned runtime container |
| `tlsCertificateFile`, `tlsPrivateKeyFile` | Projected server TLS identity |
| `databaseDSNFile` | Projected least-privileged application DSN |
| `developmentOperatorTokenFile` | Projected 64-character generated operator key |
| `migrationOwnerRole`, `applicationRole` | Distinct expected PostgreSQL role names |

Run the separate migration command before serving:

```sh
cloudring-server migrate --config /run/cloudring/migration.json
```

Migration JSON contains only `apiVersion`, `kind` set to
`CloudRINGDevelopmentMigration`, `profile`, `installationID`, `databaseDSNFile`,
`migrationOwnerRole` and `applicationRole`. Its DSN file contains the owner
credential. It has no operator key, serving TLS key or listener field. The
installer supplies resolved identities and paths; these commands do not discover
private checkouts or global configuration.

## API and browser

The TLS listener supports TLS 1.3 and bounded request/time limits.

| Method/path | Access and evidence |
| --- | --- |
| `GET /healthz/live` | Unauthenticated process liveness only |
| `GET /healthz/ready` | Current writable database and exact durable installation identity; 503 on failure |
| `GET /api/v1/provider` | Exact Bearer operator key; actual installation, operator, creation time, empty products and executable VCS/Go metadata |
| `GET /` | Sign-in page or authenticated provider readback |
| `POST /login` | Exact-origin form containing the generated operator key |
| `POST /logout` | Exact-origin form, current persisted session and CSRF token; durable revocation |

Missing/invalid API credentials return 401 without protected installation data.
Unimplemented routes return 404. User-facing paths require the configured Host
and HTTPS Origin; forwarded headers do not confer trust. Credentials in query
strings, duplicate credentials and oversized forms are rejected. There is no
cross-origin API allowance. The read-only operator does not acquire an ability
to create resources by signing in.

The portal uses a Secure, HttpOnly, SameSite=Strict `__Host-` cookie. A single
persisted browser session lasts 30 minutes and survives process/database-client
restarts. Signing in again revokes the earlier browser session; Bearer CLI access
is unaffected. Logout stores a revocation record and preserves an increasing
revision, so a delayed logout cannot revoke a newer login. It verifies revocation
before reporting success, including after an uncertain database response. Login attempts are
bounded per process. This development identity is not customer IAM or an OIDC
provider; those have separate delivery requirements.

The shell has no third-party resources, inline scripts or unverified health
labels. Database failure produces an unavailable page and failed readiness,
while process liveness remains distinct. The installer is responsible for the
client trust path, isolated origin, container/network ownership and complete
create/destroy receipt.

## Verification and remaining qualification

Focused protocol tests cover concurrent/repeated bootstrap, lost database commit
responses, foreign installation/key refusal, API denials, exact-origin checks,
session creation/rotation/expiry/restart/revocation, unavailable database state
and bounds. These tests do not claim a real installation.

The required `postgres-integration` CI job also creates a fresh random database
and application role in its disposable PostgreSQL service, performs real
migrations and the same API/browser-handler journey, closes/reopens the database
pool, and tests effective privilege drift. It verifies the new database identity
before migrations and cleans up only its captured database/role identities.
This test explicitly skips if `CLOUDRING_POSTGRES_TEST_DSN` is absent; a skipped
local run is not PostgreSQL acceptance.

C02 remains incomplete until the full public installer, signed artifacts,
upstream Kubernetes guest, real browser, independent clean-room CI, both
downstream pins and isolated hub lifecycle/restart/denial/destroy/recreate
journeys pass the existing G01 measurement profile.
