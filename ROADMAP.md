# CloudRING Roadmap

Status: accepted working plan (discussed with the owner; refines with each era).
Scope: from the current state to the full purpose of the platform. One roadmap per
repository — this file. Companion documents: QUALITY.md (quality charter),
docs/rfc/ (design records). Previous internal plans are superseded by this roadmap.

## Purpose

A lifelong cloud: a provider of one's own, free from vendor lock-in and jurisdiction
dependence, developed and operated by a single engineer with a team of AI agents; full
self-service for users; third parties extend the platform through the Open Cloud Standard
(OCS) without modifying the core. Strategic horizon: a decentralized, unkillable network
of clouds. Personally: the owner's company, number-one engineering quality, and the right
to stop.

**The purpose is achieved when all of the following hold:**

| # | Dimension | Verifiable criterion |
|---|---|---|
| P1 | Freedom | an installation ports across substrates (second adapter passes the same acceptance) and providers in different jurisdictions; user export leaves no residue |
| P2 | One engineer + agents | ≤30 min/day × 14 days of upkeep; install ≤2 h of attention; a second person repeats operations from public docs |
| P3 | Self-service | the full user and administrator journey (login, programmatic control, zero-residue lifecycle) proven on every release |
| P4 | Unkillability | ≥3 independent owners/jurisdictions at the network level; the federation runs with no central point |
| P5 | OCS is alive | ≥2 independent implementations of the contract (CNCF Sandbox will expect 3+); a third-party product runs without core changes |
| P6 | Quality #1 | comparable to or better than the leaders on every dimension; stage invariants enforced on every release |
| P7 | The company | a working commercial entity (OpenCloudTech) with the first paid event |
| P8 | A decade | the domain core carries no substrate types (substrate rotation every 5–10 years); standard stewardship institutionalized |

## Stage invariants (enforced on every release; see QUALITY.md)

I1 production-ready at every stage · I2 code is the complete source of truth · I3
reliable updates (pinned artifacts, rollback, deprecation policy) · I4 no operator IT
competence required · I5 modern architecture and process.

Strategic mandates: the core is Rust; the UI is Rust with an extension host from day one;
OCS fully implemented including the SDK — the foundation of the product; OCS never
restricts the language of connected services; docs and licenses stay current; the runtime
substrate is swappable on a ten-year horizon.

## Eras

### Era 0 — Foundation (~6–9 months; in progress)
Deliver from code alone (parity), enforce process gates (CI tiers, regression gate,
coverage floor, e2e and upgrade tests, SLSA L2), land OCS 1.0 + Rust SDK + conformance,
the first Rust vertical slice under the M1 behavioral acceptance, the Rust UI with an
extension host, finish M2/M3, the GUI installer, and the second substrate adapter.
**Exit:** the platform deploys and updates from code alone on a clean cluster with zero
manual steps; the behavioral acceptance is green; an external user lives on it.

### Era I — The 1.0 product (~9–18 months after Era 0)
The full mandatory catalog (Network, Volume, Image, Compute, Kubernetes, S3, Backup,
Access, Support — each proven on a real backend including failures). A second
independently managed site; a second engineer repeats operations from the docs; the 1.0
measurements (regional RPO 0 / RTO ≤5 min; off-cell RPO ≤15 min / RTO ≤60 min; ≥99.95%
availability over 24 h). A release train with n-2 support, canaries, and rollback. One
license policy.
**Exit:** 1.0 released; entry into Era II at ≥3 external independent installations
(proposed threshold — the owner confirms or sets their own).

### Era II — The OCS ecosystem (~1–2 years, overlapping growth)
The standard lives outside one repository: specification separate from implementation;
≥3 independent implementations (including ≥1 not ours); a conformance program with a
public registry (CNCF model); a marketplace with mandatory signing. First third-party
products in production at external users. Stewardship: a technical committee, a public
standard roadmap, an RFC process.
**Exit:** OCS is a language ≥3 independent teams speak without our participation.

### Era III — World adoption (~2–4 years)
The public cloud + partner installations; the community machine (good-first-issues,
mentorship programs, multi-organization maintainers — the strongest survival predictor);
CNCF Sandbox (once 2–3 independent implementations exist) → Incubating (CNCF criterion:
3+ independent dev/test adopters; our bar: production adopters) → Graduated (maintainers
from ≥2 organizations). "Thousands of companies" follows the Kubernetes adoption curve
(83% production share four years from announcement under the foundation model).
**Exit:** the platform is a top-3 choice for a new private/sovereign cloud; the standard
is de facto.

### Era IV — The unkillable network (~3–5 years, overlapping III)
Provider federation: the P2P bus, cross-cloud connect, settlement (per the transformation
plan, its 18–36-month horizon); ≥3 jurisdictions at the network level; no jurisdiction,
company, or single operator can switch the network off (P4). Decentralized governance of
the standard (foundation/association).
**Exit:** purpose dimensions P1–P8 are met and confirmed by external audits.

## Stewardship and economics (cross-cutting; owner decisions)

- Era 0: IP held by Elena Trukhina ZZP; OpenCloudTech is the intended future owner
  ("ethereum foundation" model) — transfer not yet executed; stewardship form is an
  Era II decision.
- Monetization per the transformation ladder: the OSS core is free; the Business tier
  (licenses/support/maintenance) from Era I; marketplace revenue sharing from Era II+.
  Thresholds are the owner's decision (no thresholds exist in the sources).
- The team: one engineer + an agent team; "one engineer" is an operating invariant, not
  an organizational cap; the hiring trigger (proposed: when P2 genuinely breaks) is the
  owner's call — the sources do not set one.

## Progress control (cross-cutting)

- Every era has entry/exit criteria above; invariants I1–I5 hold on every release.
- Track life metrics (cores, installations, external products), not hype metrics
  (stars, summits) — the OpenStack lesson.
- Stop-losses: N iterations without progress → stop, re-plan, escalate to the owner.

## Honest limits

Era durations are orientation from precedents (Linux 26 years; Kubernetes 4 years from
announcement; the OpenStack hype/life divergence). No public case exists of an agent team
running a production OSS platform for years — our compass is behavioral acceptance plus
gates, not trust. Public clouds die in 2–6 years against hyperscalers: the speed of Eras
0–II is survival, not a race.
