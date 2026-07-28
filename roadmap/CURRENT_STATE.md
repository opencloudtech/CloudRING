# Public current state

Snapshot reviewed: 2026-07-28.

This document is a public orientation aid. It contains no private deployment
inventory or downstream status. [`roadmap.yaml`](roadmap.yaml) is the single
canonical delivery-order and compact-status authority; this narrative cannot
advance a goal.

## Maturity legend

| State | Meaning |
| --- | --- |
| `implemented` | Source and tests exist for the stated repository-level use case. |
| `reference` | A runnable or testable example demonstrates a contract. |
| `experimental` | Early implementation may change and is not a production promise. |
| `planned` | Owned by a canonical roadmap goal but not implemented. |
| `blocked` | A known missing acceptance condition or public defect prevents the stated use. |

## Capability matrix

| Capability | Public state | Evidence and boundary |
| --- | --- | --- |
| Build, unit/race/vet, source-safety, and supply-chain checks | `implemented` for repository validation | Workflows and Go tests validate the accepted source revision; they do not prove a deployed cloud. |
| OCS package types, validators, Go SDK, fixtures, and conformance tooling | `reference` / `experimental` | Packages and synthetic modules are testable. OCS 1.0 compatibility, a complete product runtime, and independent product release proof remain planned. |
| Identity, OIDC/JWT, IAM-policy, secure-session, and audit primitives | `reference` | Reusable primitives exist. A complete serving identity platform, durable production authorization path, and full recovery lifecycle are not delivered. |
| Transactional PostgreSQL state and migrations | `reference` | A reusable implementation and tests exist; it is not yet the complete provider-control-plane state model. |
| Provider adapters and site profiles | `experimental` | Public schemas, validation, and synthetic inputs exist. Concrete provider accounts and inventory are outside the public boundary. |
| kubeadm rendering and Kubernetes deployment profiles | `blocked` for independent installation | Public issues document missing executable substitution/join paths, schema integration, topology validation, and storage dependencies. A complete supported installer is not available. |
| Backup, proof signing, restore collection, and resilience observers | `reference` / `experimental` | Reusable collectors and protocols exist. Integrated off-site recovery and promotion-grade failure campaigns are not publicly proved. |
| Three-node and one-server-loss material | `reference` | It tests one declared single-failure topology. It is not a universal HA topology or production availability promise. |
| Provider control plane, organization model, inventory reconciliation, durable operations, and portal | `planned` | Owned by G03-G11 and the provider-control-plane public issues; no complete runtime exists. |
| Network, volume, image, compute, Kubernetes, object storage, backup, access, support, and external products | `planned` | Goal contracts exist, but the products are not complete public runtime capabilities. |
| Multi-cell, multi-region, marketplace economics, and sovereign federation | `planned` | Explicit later roadmap work. No current implementation or availability claim. |

## Publicly known blockers

The open issue tracker is the defect and work-item record. In particular:

- issues 23-38 describe the missing provider-control-plane MVP;
- issues 81-82 cover one-server-loss observation correctness;
- issues 83, 85, 92, 93, and 97 block a truthful independent-installation claim;
- issues 90, 91, and 96 cover snapshot/restore and storage-profile gaps;
- issues 86, 89, and 94 cover security, IAM, and SafePush gaps;
- issues 88 and 95 cover dead or insufficiently strict public contracts.

Issue closure requires its complete acceptance criteria and regression tests.
Closing a document gap alone does not promote a runtime capability.

## Availability direction

Current reference fixtures frequently use three control-plane members and a
single-node loss. The portable design direction is a topology-neutral contract
covering failure domains, quorum, replication, endpoint continuity, workload
availability, RPO/RTO, and measured SLOs. That direction is planned; no current
document should be read as implementing it.

## What a fresh reader can safely do

- build and test the repository;
- validate public OCS packages and synthetic reference modules;
- inspect and exercise public validators and reference contracts;
- contribute provider-neutral code, documentation, tests, adapters, and modules.

The current repository is not ready for production use. A fresh reader should
not treat a reference profile, green CI run, fixture, or roadmap document as a
release or deployment claim.
