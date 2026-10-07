# Ownership

CloudRING separates the reusable public platform from independently owned
services, provider businesses, and deployment-specific material.

Copyright attribution is stated in [NOTICE](NOTICE). Yuri Trukhin stewards the
repository and maintains the project naming policy in [TRADEMARKS.md](TRADEMARKS.md).
Copyright in an independent contribution remains with its copyright holder unless
it is transferred under a separate agreement. The Apache License 2.0 governs material
distributed under this repository's license; third-party material retains its
own terms.

## Public platform scope

The public project is the intended home for reusable, provider-neutral material
such as:

- the provider-neutral control-plane runtime and public APIs;
- OCSv3 contracts, SDKs, validators, conformance tooling, and reference modules;
- identity, IAM, policy, admission, audit, catalog, billing foundations, portal,
  and self-service platform capabilities;
- GitOps, installation, evidence, readiness, lifecycle, backup/restore,
  upgrade, rollback, release, and operations tooling;
- open source service modules and reusable provider adapters accepted under the
  repository's contribution and licensing terms;
- developer, operator, security, and user documentation.

Project maintainers decide whether material distributed through this repository
conforms to its published contracts. The project does not acquire ownership of
an independent implementation merely because that implementation uses OCSv3.

## Independent services

An independently developed service remains owned and licensed by its author
unless it is intentionally contributed to CloudRING. Its owner controls its
implementation, release cadence, commercial terms, and distribution subject to
applicable law and agreements.

To integrate as a first-class product, the service publishes the OCSv3 metadata
and APIs required for lifecycle, IAM, portal, billing, support, observability,
durability, backup/restore, upgrade/rollback, export/deletion, and failure
states. The platform consumes those declared interfaces without importing the
service's private internals.

## Providers and deployments

Each provider owns and operates its business, customer relationships, capacity,
local policies, admitted module catalog, commercial terms, and legal compliance.
CloudRING compatibility does not imply endorsement, certification, shared
ownership, or operational responsibility by the CloudRING project.

Account-, topology-, customer-, and installation-specific configuration;
credentials; customer data; private endpoints; live support records; and live
evidence remain with the deployment owner. A reusable adapter belongs in public
only when it is intentionally contributed and source-safe.

## Federation and commercial relationships

Future federation does not create a common owner of participating providers or
modules. Product publication, licensing, marketplace admission, settlement,
revenue sharing, support, and liability require explicit agreements and
machine-readable policy where appropriate. No such relationship is implied by
using CloudRING or OCSv3.

## Trademarks

Open source licensing does not grant trademark rights. See
[TRADEMARKS.md](TRADEMARKS.md) before naming or marketing a compatible module,
fork, hosted service, or downstream distribution.
