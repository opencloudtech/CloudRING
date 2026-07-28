# G00 — Truthful baseline and protected delivery

## Outcome

Create one lossless, reproducible, and protected delivery path across public OSS,
an independently controlled clean-room consumer, and the maintained public
reference installation. At the end of this goal, all accepted public work is
visible in remote `main`, clean-room consumers agree on the intended public core,
and no readiness claim depends on an unclassified worktree, stale evidence, or a
broken gate.

## Scope

- Refresh remote mains, branch protections, required checks, open PR/MR, issues,
  submodule pins, releases, toolchain and live GitOps revision.
- Inventory every registered worktree, dirty file, patch, local-only commit and
  stale process. Assign owner, provenance, requirement and disposition. Preserve
  useful WIP in source-safe checkpoint branches; do not bulk merge or delete it.
- Recreate clean canonical checkouts from current remote mains. Never use a
  divergent or dirty checkout as a release source.
- Remove remaining OMO/LazyCodex runtime residue from accepted product trees and
  enforce its absence without deleting historical evidence required by law or
  support.
- Reproduce, classify and assign every public issue in `ISSUE_MAP.md`. Fix in G00
  only defects that invalidate the truthful checkout, boundary or delivery path.
  Product, installer, IAM, storage, backup and resilience defects stay open until
  their owning goal proves full acceptance.
- Fix the clean-room delivery TLS identity without disabling verification,
  rerun the exact downstream merge pipeline, land the current public-core pin,
  and verify the resulting protected `main` pipeline.
- Add a periodic signed-receipt canary plus certificate-expiry, SNI, runner
  liveness and recovery alerts for SafePush. Define and test a bounded recovery
  procedure without persisting runner credentials on disk.
- Verify protected PR/MR-only mains, strict current-base checks, no force/delete,
  founder self-review without check bypass, and founder/maintainer approval for
  other contributors.
- Create a tracked public requirement ledger and capability matrix under
  `roadmap/state/`, validated by `roadmap/state.schema.json`. Downstreams may
  record protected evidence references outside this repository but must not fork
  canonical requirements.
- Populate `HUB_PREREQUISITES.md` with live owner, isolation, capacity, cost,
  credential, mutation, rollback and cleanup status for every later goal.
- Add machine checks for public/private ownership, generic duplicate detection,
  exact submodule pins, stale claims and issue-to-regression traceability.

## Required delivery

1. Public OSS clean clone passes the complete required test and source-safety
   suite with no open bug known to invalidate current behavior.
2. A clean-room downstream contains no duplicate implementation of capabilities
   already accepted in OSS and has no non-public platform dependency.
3. The downstream pins the accepted public SHA and passes its protected delivery
   and signed-receipt checks.
4. The exact accepted public release is reconciled to the maintained reference
   installation; reachability, TLS, anonymous denial, revision, and rollback path
   are freshly reverified.
5. A sanitized baseline report records exact remote SHAs, pins, open blockers and
   current non-claims. It does not embed secrets, private inventory or raw logs.
6. The issue map, hub prerequisite ledger, state/evidence schemas and machine-
   readable goal states validate in CI and contain stable requirement IDs.

## Acceptance

- No useful change exists only in an untracked file, local commit or open green
  PR/MR without an explicit owner and next action.
- All accepted repository mains are cleanly reproducible from a fresh clone.
- SafePush positive and negative qualification pass; a deliberately invalid
  candidate is rejected.
- Public issue list contains no unresolved defect that contradicts the baseline
  capabilities claimed complete by this goal.
- The reference installation is stable before and after the baseline rollout;
  this baseline does not claim broad live release qualification.

## Non-goals

This goal does not build missing platform products. It establishes truthful
delivery and fixes known defects so subsequent goals start from a trustworthy
base.

## Completion statement

G00 is complete only after the remote-main and live readback chain is green and
the WIP ledger accounts for every non-clean worktree without losing user work.
