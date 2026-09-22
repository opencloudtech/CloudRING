# Governance

CloudRING governance exists to keep the public platform cohesive, portable, and
safe for independent providers, enterprises, and service teams to adopt without
maintaining incompatible copies of the generic core.

## Project direction

The project follows [VISION.md](VISION.md) and the evidence-gated sequence in the
[public roadmap](roadmap/README.md). Long-term ambition does not override
current non-claims: a capability becomes project truth only when it is accepted
in the public repository and verified at the scope claimed.

OpenCloudTech stewards the repository and decides which contributions are
accepted. Governance should broaden over time as active maintainers and
independent provider or service contributors demonstrate sustained ownership.
Until a governance change is documented here, no affiliation, deployment, or
module publication grants decision authority by itself.

## Platform authority

CloudRING maintainers govern the public runtime, APIs, OCSv3 contracts,
compatibility policy, validation rules, release gates, module registry behavior,
evidence semantics, accepted modules and adapters, and public documentation.

Platform decisions must preserve:

- provider and implementation neutrality;
- documented first-class extension surfaces;
- local provider autonomy and fail-closed security;
- data exit, lifecycle, durability, and evidence boundaries;
- the separation of reusable public code from deployment-specific material.

Decisions that affect downstream implementers should be recorded in public
documentation, versioned contracts, tests, or an architecture decision record.

## Review and acceptance authority

The project founder and lead maintainer, `@trukhinyuri`, has final review and
acceptance authority for CloudRING, including founder-authored changes. Such a
change does not require a separate independent approver, but it must retain a
reviewable pull request, an exact-head owner review, all required SafePush
checks, resolved conversations, and post-merge verification. Automated or AI
assistance may support review, testing, and evidence; the human maintainer
remains accountable for acceptance.

Changes from every other contributor require founder approval, or approval by
a reviewer explicitly delegated in a future documented governance change, in
addition to the same required checks. Maintainer or administrator access is not
permission to bypass this process.

## Service and provider autonomy

CloudRING maintainers govern modules distributed in this repository.
Independent module maintainers govern their own implementations, release
cadence, licenses, portal extensions, billing connectors, support diagnostics,
evidence, and lifecycle behavior. CloudRING maintainers decide whether a module
is officially listed or recognized by the project as compatible with the
current public contracts. Independent factual claims remain subject to the
published conformance requirements and [trademark policy](TRADEMARKS.md).

Each provider controls module admission, local policy, commercial terms,
capacity, customer commitments, and legal compliance for its deployment.
Future federation must be opt-in and must not transfer root authority or make
one provider dependent on another's continued participation.

## Enterprise and private boundary

Enterprise modules, proprietary integrations, company overlays, concrete
installation values, and customer deployment records are governed by their
owners. Reusable adapters and services may become part of CloudRING only through
an intentional, licensed, source-safe contribution.

## Changes to governance or OCSv3

A proposal that changes governance, compatibility, contribution terms, OCSv3
semantics, or the public/private boundary must:

1. state the problem and affected participants;
2. document compatibility, security, ownership, and exit consequences;
3. include a migration or versioning path when existing contracts change;
4. receive the required maintainer review and pass all repository gates;
5. update the public documents and machine-readable contracts together.

## Documents

- [QUALITY.md](QUALITY.md) — quality charter: stage invariants, regression policy, reference-platform aim.

- [ROADMAP.md](ROADMAP.md) — the single product roadmap: purpose, eras, exit criteria.
