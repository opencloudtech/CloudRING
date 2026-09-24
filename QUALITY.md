# CloudRING Quality Charter

This charter is the repository-owned statement of product quality requirements. It binds
every contribution, release, and milestone: CloudRING must be a stable, production-grade
product at every stage of its evolution — not only at major releases — and it must deploy,
operate, and update reliably from code alone.

## Invariants (enforced at every stage)

1. **Production-grade at every stage.** Every merge leaves the platform stable and
   operable. Intermediate states that degrade availability, installability, or
   upgradeability are defects, not milestones. Acceptance of any stage includes a clean
   install and a clean upgrade from the previous accepted state.
2. **Code is the complete source of truth.** Anything required to run the platform lives
   in this repository (or in artifacts built from it by the release pipeline). Ad-hoc
   cluster objects without a repository counterpart are drift and must be reconciled in
   the same change that introduces them.
3. **Reliable updates.** Updates ship through the release pipeline with pinned,
   verifiable artifacts (digests, provenance), a defined rollback, and a deprecation
   policy. Breaking changes follow the documented compatibility contract.
4. **No operator IT competence required.** Deployment and day-2 operations are driven by
   the installer and the portal, not by terminal competence. The graphical installer is a
   product surface maintained with the same rigor as the API.
5. **Modern architecture and process.** Control planes are declarative and reconcile-based;
   CI enforces unit, integration, and end-to-end tiers plus upgrade testing; releases
   follow semantic versioning with published support windows; reliability is managed with
   SLOs and error budgets.

## Regression policy

- A regression is any accepted change that breaks a previously passing behavior, check, or
  documented requirement. Regressions are not traded for features; they are fixed before
  the next release, and their cause becomes a new or strengthened automated check.
- Required status checks are the minimum bar, not the goal. Coverage, lint, security
  scanning, and manifest-verification gates may only become stricter over time; weakening
  a gate requires an explicit, reviewed justification recorded in the pull request.
- Every user-visible behavior fixed in a change is covered by a regression test that fails
  before the fix and passes after it.

## Becoming the reference platform

The product aims to be the reference open cloud platform across code quality, reliability,
testing, security, isolation, UX, API and CLI design, scalability, extensibility, absence
of single points of failure, and operability by humans and AI agents alike. Progress
against each dimension is tracked in the roadmap; claims are backed by evidence in the
acceptance records, not by intent.

This charter is maintained like code: changes arrive by pull request with review, and the
charter is binding for all CloudRING repositories.

The stage invariants of this charter are enforced through the roadmap in [ROADMAP.md](ROADMAP.md).
