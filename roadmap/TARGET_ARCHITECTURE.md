# Target architecture and durable design boundaries

## Product shape

CloudRING is a provider control plane plus independently developed cloud
products. The provider control plane is useful without products: it supplies a
standalone-capable identity service, tenancy, IAM, API, CLI, portal, catalog
administration, operations, billing and provider lifecycle. Products are
installed only through OCS and use one of three explicit execution profiles:
`local`, `remote` or `api-only`. A product may run in the platform cluster, in
another cluster or region, at another provider, or behind an existing external
API; none of those placements may require product-specific code in the platform
kernel.

The architecture has three planes:

1. **Provider management plane** — provider identity, global organization/tenant/project
   directory, product governance, commercial policy, regional placement and
   cross-region/federation coordination.
2. **Regional cells** — bounded failure and scale units containing regional API
   workers, lifecycle controllers, transactional state, network/storage/compute
   bindings and product connectors. A cell owns a bounded tenant/resource set.
3. **Product data planes** — workloads and infrastructure operated by OCS
   products. Their high-volume data path does not transit the management plane.

The first production release has one region and one cell, but the ownership,
identifiers and APIs must not assume that one is universal. More cells are added
only after the single-cell platform is complete and measured.

## Stable platform kernel

The kernel is deliberately small:

- canonical resource names and hierarchy: provider, region, cell, organization,
  tenant, project, product, offering, entitlement, resource and operation;
- identity and session verification;
- hierarchical role and condition-based IAM;
- durable operations, audit and event delivery;
- catalog, order, subscription and entitlement state;
- metering, rating, quota, capacity and financial ledgers;
- extension discovery and policy-enforced API/UI routing;
- upgrade, compatibility and support contracts.

Management-plane substrate dependencies are not tenant-visible products. They
include Kubernetes, networking needed by the platform itself, certificates,
secrets, transactional storage, GitOps and telemetry. They are installed and
upgraded by the platform distribution and are not placed in the customer catalog.
Reference infrastructure offerings such as tenant network, volume, VM and object
storage are installable OCS products. This distinction keeps “zero installed
products” meaningful without pretending the management plane has no dependencies.

## Open Cloud Standard

OCS is a versioned product contract, not a Go interface or Kubernetes-only CRD.
It must define:

- product identity, ownership, versions and compatibility;
- an explicit `local`, `remote` or `api-only` execution profile and only the
  placement-specific contracts that apply to that profile;
- signed OCI-distributed package metadata;
- synchronous APIs described by a pinned OpenAPI profile;
- asynchronous events described by CloudEvents and a pinned AsyncAPI profile;
- durable operation, idempotency, retry, cancellation and compensation rules;
- a capability/action matrix for provision, hold/suspend, resume, resize and
  deprovision. Each action is either `supported` with its complete contract or
  `not_applicable` with a machine-readable reason; products never implement
  meaningless fake actions merely to satisfy conformance;
- discovery, health, readiness, durability, support and observability;
- mandatory user and administrator API exposure through a product namespace in
  the provider gateway, including versioned product-specific APIs selected by
  the product team without adding product logic to core;
- an optional signed, capability-scoped portal extension. A product without one
  remains completely operable through API, CLI and agent-safe automation;
- an explicit billing policy (`metered`, `zero-priced-metered` or
  `non-billable`), plus applicable meters, dimensions and rating inputs;
- offering, entitlement, audience, region, quota and capacity declarations;
- tenant and project isolation;
- service-to-service consumption through infrastructure-user identities and
  entitlements, with region compatibility, quota/capacity reservation and
  billing attribution to the consuming product team;
- local and remote connector identity, transport and trust negotiation;
- package install, moderation, rollout, rollback, upgrade and removal;
- positive and negative conformance suites plus compatibility fixtures.

Until G27, the standard is an OCS release candidate whose compatibility is
falsified by real independent products. G27 freezes OCS 1.0 only after at least
two real local products and one remote product pass lifecycle, upgrade and
negative conformance. OCS is a CloudRING project specification, not an accredited
international standard or certification scheme unless that status is obtained
separately.

The standard supplies generated clients and a Go SDK first, server stubs, test
doubles, a local product harness, conformance helpers and package tooling. Its
wire contracts are language-neutral; additional SDKs are generated from the same
schemas after the Go reference is stable. The SDK must not require importing
platform internals or access to non-public source. A clean-room product team must
be able to implement, test, package and publish independently.

## APIs and operations

Use resource-oriented HTTP APIs with consistent naming, pagination, filtering,
field masks, optimistic concurrency, idempotency keys and stable structured
errors. Any action that can exceed a short request returns a durable Operation.
Operations survive process restarts, expose progress and audit, and have explicit
cancellation and retry semantics.

Events are at-least-once. Consumers deduplicate by stable event and operation
identity. A transactional outbox prevents accepted state from losing its event.
Backpressure, deadlines, bounded retries, jitter and retry budgets prevent one
product or tenant from causing a cascade.

The human portal, CLI and AI-agent adapters are clients of the same public API.
No capability may exist only in a hidden UI or private operator script. Agent
automation requires scoped short-lived credentials, dry-run/plan, approval gates,
idempotency and a complete audit trail. An MCP adapter may be supplied, but core
must remain independent of any one agent protocol.

The provider owns product admission and commercial exposure. A package proposes
capabilities and publisher-owned metadata; an installation administrator decides
whether a revision is admitted, which offerings are enabled, in which regions,
for which selected principals, tenants or cohorts, and when an offering becomes
public. Package metadata can never grant itself visibility or entitlement.

## Identity and trust

Human authentication uses standards-based OIDC, secure session lifecycle and
WebAuthn/passkeys with supported recovery. Workload identity is short-lived,
attested and designed for SPIFFE-compatible federation. IAM combines inherited
roles over the resource hierarchy with safe, bounded conditions such as CEL; it
does not attempt to clone every historical AWS IAM feature.

The CloudRING identity service can operate as the installation's complete IdP
for users and workloads while also federating external OIDC providers. Requiring
an external identity vendor for a functional provider is not allowed.

All authorization is evaluated fail-closed at the API boundary and again by the
executing controller or connector. Break-glass access is time-bound, separately
approved, visible and immutable in audit.

## Data and billing

PostgreSQL is the initial source of truth for transactional provider state. Each
module owns its schema and migrations; cross-module access uses stable domain
interfaces rather than ad hoc table reads. HA, synchronous durability for the
declared failure domain, PITR, off-cell backup and restore drills are mandatory.

Usage is append-only, idempotent and attributable to tenant, project, product,
resource, region, cell and infrastructure user. Rating versions are immutable.
Money uses exact decimal arithmetic with explicit currency, rounding, proration,
tax boundary and correction semantics. The financial ledger is double-entry.
FOCUS-compatible cost export is provided without forcing internal models to be a
copy of the export schema.

Portable packages may carry a publisher price proposal and licensing references,
but effective price books, provider commission, taxes, approval and payout policy
belong to the installation. Publisher proposals and provider commercial policy
are separately versioned, approved and audited; a product package cannot set its
own effective provider commission.

## Deployment and operations

Desired state is declarative, versioned, pulled and continuously reconciled.
Installations use upstream Kubernetes APIs, GitOps and provider/site adapters.
The generic installer owns validation, planning, bootstrap, upgrade, rollback and
diagnostics; downstream repositories supply inventory and bindings only.

All serving components are horizontally replicated or explicitly outside the
production claim. The platform API, portal, identity, IAM decision path, billing
ingest/rating/ledger/read paths and their transactional stores have no single
serving replica or node whose supported loss stops eligible work. Stateful
quorum, disruption budgets, topology spread, anti-affinity, overload protection,
autoscaling, capacity thresholds and tested failover eliminate single-instance
readiness. Data-plane products declare their own failure domain and SLO.

Updates use compatible rolling or blue/green release, expand/migrate/contract
database changes, version negotiation and automated rollback barriers. Blue/green
is selected when a rolling release cannot preserve the declared continuity
contract; it is not required mechanically for every component. Supported
upgrades must preserve eligible API requests, accepted operations, identity/IAM
decisions, usage ingestion, balanced ledgers and valid invoices. A release is
never promoted solely because Kubernetes objects became Ready.

OpenTelemetry-compatible traces, metrics and logs, correlated audit, SLOs,
alerts, capacity forecasts, support bundles and guided repair workflows are part
of the product. The default operational experience favors a small number of
well-understood components and automated diagnosis over a large bespoke stack.

## Scale and federation

Scale up a cell to its measured safe envelope, then add a cell. Tenant placement
is durable and explicit; noisy tenants cannot starve system or other-tenant work.
Cells deploy and fail independently. Management-plane loss must not terminate
already running product data planes.

Provider federation is a post-1.0, opt-in extension of a complete standalone
provider; the 1.0 release does not depend on multi-region or federation runtime.
Federation never shares a database, root administrator or mandatory central
coordinator. Providers exchange signed identities, catalogs, offers, orders,
entitlements, usage summaries and settlement records with replay protection,
store-and-forward behavior and revocation. A provider opts in to each relationship
and retains policy and legal control over what it exposes. Existing peers and
local products continue according to declared partition policy when any provider,
directory or jurisdiction disappears; no single company, service or trust root
can switch off the whole network.

## Explicitly rejected architecture

- a microservice per noun before real independent scale or ownership exists;
- direct product integration into platform internals;
- a universal shared database across products or providers;
- synchronous chains for long-running infrastructure changes;
- a central federation root whose outage disables the network;
- UI bundles that execute unsigned remote code with provider credentials;
- unbounded queues, retries, caches or tenant workloads;
- one giant regional control plane expected to scale forever;
- site-specific fixes kept downstream when the defect is generic;
- documentation, schemas, fixtures or green manifests presented as runtime.
