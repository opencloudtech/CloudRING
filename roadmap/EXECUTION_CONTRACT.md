# Execution contract for all roadmap goals

## Authority and truth

- This roadmap is the program charter.
- Versioned public requirements and schemas are normative product contracts.
- Remote `main`, exact git trees, required checks and live readback are factual
  truth about delivery.
- Evidence is useful only when it is sanitized, tied to an exact accepted SHA,
  scoped to the requirement it proves and still fresh for that requirement.
- Historical plans, local branches, open PRs/MRs and green fixture-only tests do
  not prove delivery.

## Repository ownership

`opencloudtech/CloudRING` owns every reusable capability: platform kernel, OCS,
SDKs, API conventions, identity and IAM, billing semantics, installers,
controllers, reference products, operations, conformance, security and docs.

Downstream operators own their concrete provider, site, and jurisdiction
bindings, private configuration references, protected inventory, and live
evidence. A downstream may pin this public source, but CloudRING must remain
buildable, testable, understandable, and usable without access to that
downstream.

When a downstream environment exposes a generic defect, fix it in OSS first,
merge it, update the affected consumer pin, remove any temporary workaround and
rerun the affected acceptance journey.

## Agent team

One root orchestrator owns the requirement ledger, architecture decisions,
integration, credentials, live mutations, reviews, merges and release verdict.
Use at most four concurrent implementation lanes:

- OSS implementation;
- reference-deployment propagation and live preparation;
- independent downstream clean-room verification;
- read-only verification and red-team review.

Write-heavy lanes use separate persistent worktrees and non-overlapping path
ownership. Workers receive a bounded task packet containing requirement IDs,
base SHA, allowed paths, acceptance tests, live applicability and non-claims.
They do not receive credentials and do not mutate live systems.

The founder (`trukhinyuri` / `ytrukhin`) may technically review and merge their
own PR/MR after every required check passes. No artificial second reviewer is
required for founder changes. Other contributors require founder or designated
maintainer approval. Direct or force push to protected `main` is forbidden for
everyone.

## Goal workflow

For each goal:

1. Refresh current remote mains, open work, issues, pins and affected live state.
2. Load the stable requirement IDs, applicability decisions and issue ownership
   already assigned in this roadmap; add IDs only through a reviewed roadmap
   change, never ad hoc inside implementation.
3. Recover only relevant WIP after classifying provenance and diff; never bulk
   merge a historical worktree.
4. Deliver the smallest complete vertical slice that satisfies the goal; do not
   replace it with interfaces, manifests or documentation.
5. Review exact diffs and run unit, integration, negative, concurrency,
   migration, upgrade and failure tests applicable to the slice.
6. Merge through protected OSS `main`.
7. Produce an immutable signed prerelease artifact for the goal with SBOM,
   provenance, compatibility record and exact source SHA.
8. Prove the public clean-room journey without any non-public source.
9. Verify at least one independently controlled downstream pin to the exact
   accepted OSS SHA when the goal requires portability. Consumer-specific
   changes stay in that downstream and pass its protected delivery policy.
10. Reconcile the exact accepted public release to the maintained public
    reference installation when the goal requires live deployment.
11. Run the goal's live human/API/CLI/agent journeys, every previously delivered
   regression journey, rollback/failure checks, drift checks and current SLOs.
12. Comment on and close only issues whose complete acceptance criteria are now
    proved; add regression tests before closure.
13. Record evidence using the versioned roadmap evidence schema, exact final
    SHAs and cleanup receipt, then mark the goal complete.

`roadmap.yaml` is the compact status index. From `in_progress` onward, the
matching `roadmap/state/GNN.json` record is authoritative detail; CI must reject
an index/state mismatch, an invalid dependency transition or delivered state
without immutable proof. The evidence validator additionally enforces
`expiresAt > observedAt`, goal-specific freshness ceilings, verified
attestations, resolvability, the exact goal-specific deployment target set, pin
equality and the protected/public redaction policy defined in
`EVIDENCE_POLICY.md`; JSON Schema alone cannot express those semantic checks.

Only one active write PR/MR per repository is allowed. Read-only research and
verification may proceed in parallel. A compatible batch of already accepted
public commits may share one downstream pin, but each requirement must remain
traceable.

## Universal definition of done

A goal is complete only when all applicable cells are green:

- real serving API or executable controller;
- authentication, authorization and tenant isolation;
- durable state, schema migration and transactional integrity;
- stable errors, idempotency, concurrency control and cancellation;
- asynchronous operation state where work can outlive a request;
- complete lifecycle including recovery and deletion;
- API, CLI, portal and agent-safe automation where user-facing;
- metering, quota, capacity and billing where a sellable resource is involved;
- logs, metrics, traces, audit, health and actionable alerts;
- HA, backup, restore, upgrade and rollback for stateful production paths;
- positive, negative, restart, failure and load tests;
- accurate operator, user and developer documentation;
- no reachable production placeholder, mock, fixture, hardcoded success or
  `not implemented` behavior;
- green required CI and supply-chain checks on the exact accepted commit;
- exact downstream pins for every applicable clean-room consumer;
- successful rollout and acceptance at `hub.cloudring.org`;
- no unclassified WIP or unresolved issue that contradicts the goal claim;
- generic downstream duplication for every surface touched by the goal has been
  removed after its OSS replacement landed. Temporary compatibility code has an
  owner, expiry, replacement SHA and a guard against further development.

An explicit, reviewed `n/a` is allowed when a cell truly does not apply. It must
state why. Applicability is not a loophole for postponing required behavior.

## Quantitative product objectives

These are release targets, not claims about the current system:

- Reference management-plane availability objective: at least 99.95% monthly
  within one declared region after G27. Release qualification uses the shorter
  soak defined in `MEASUREMENT_CONTRACT.md`; it cannot claim a month not observed.
- The platform API, portal, ID, IAM and billing ingest/rating/ledger/read paths
  must each tolerate the supported loss of one serving replica or node without
  losing accepted work, granting access incorrectly or producing invalid money.
- No committed transactional data loss during a supported single-node failure;
  regional business-state RPO 0 for that failure and automated failover target
  RTO no more than 5 minutes.
- Off-cell backup target RPO no more than 15 minutes and reference restore target
  RTO no more than 60 minutes for the documented reference dataset.
- Supported zero-downtime upgrade: no failed eligible request attributable to the
  release, no readiness-probe unavailability, no lost accepted operation, no data
  loss and no invalid billing. Long-lived clients may reconnect only when their
  protocol explicitly supports transparent resume. Measurement follows
  `MEASUREMENT_CONTRACT.md`.
- Every resource mutation returns or references a durable operation within the
  numeric acknowledgement threshold frozen in its active measurement profile;
  synchronous request latency is not held hostage by provider execution.
- A documented fresh installation, after hardware/network prerequisites exist,
  requires no source changes and no more than two hours of operator attention.
- Routine healthy-state operation requires no more than thirty minutes of human
  attention per day; diagnostics and support bundles are generated in under five
  minutes without exposing secrets.
- A mid-level developer can create, run, test and package a conformant service
  from the public SDK and docs in no more than two hours, without changing core.
- Each published release has a measured capacity envelope. Scale tests must show
  bounded resource use, backpressure and no tenant starvation. Scale claims are
  tied to hardware and workload profiles, never an unqualified request count.

If these targets prove physically unrealistic on the reference hardware, the
goal must expose the measured constraint and improve architecture or capacity;
it may not silently weaken the target and claim success.

## Simplicity rules

- Begin with a modular Go control plane and Kubernetes controllers. Split a
  process only for a proven independent scaling, trust, ownership or failure
  boundary.
- PostgreSQL plus a transactional outbox/inbox is the default durable backbone.
  Do not add a distributed broker until measured demand or isolation requires it.
- Do not use event sourcing for ordinary CRUD state; reserve append-only ledgers
  for audit, usage and financial records.
- Do not introduce a service mesh, custom scheduler, custom database, custom
  workflow language or custom cryptographic protocol when a maintained standard
  satisfies the requirement.
- Product services never read another service's database. They integrate through
  OCS APIs/events and explicit infrastructure-user entitlements.
- Every OCS product declares `local`, `remote` or `api-only` execution and a
  capability/action applicability matrix. Public API behavior is mandatory;
  a signed sandboxed microfrontend is optional and cannot be required for
  API/CLI/agent completeness.
- Provider policy owns admission, audiences, offered regions, effective prices
  and commission. Portable packages cannot grant their own visibility or set
  effective installation commercial policy.
- Platform core must run and pass readiness with zero installed products.
- One product is completed before starting the next. Shared abstractions are
  extracted from at least two real uses, not invented speculatively.
- Generic observability, backup, failure behavior, upgrade, rollback, diagnostics
  and provider packaging are implemented incrementally in every applicable goal.
  G22-G24 are integrated certification campaigns, not the first implementation of
  those properties.

Native Windows is not a release gate unless a component explicitly claims Windows
support. No Windows support claim is allowed without native verification.

The CloudRING 1.0 dependency path ends at G27 after G24. G25 multi-region and
G26 sovereign federation are opt-in post-1.0 tracks; neither can block, satisfy
or weaken standalone 1.0 acceptance. Their later releases repeat the applicable
broad security review after their functionality is complete.

## Live change safety

Only the root orchestrator performs a live mutation. Before each mutation record
the exact accepted SHA, resources, pre-state, dry-run, expected result, disruption
budget, rollback, abort conditions and cleanup. Security-sensitive or potentially
disruptive changes require an exact approval tuple immediately before apply even
when routine repository work has standing authorization.

The G00 hub-prerequisite ledger must show capacity, cost authority, credentials,
test isolation and rollback feasibility before a goal starts live work. A missing
prerequisite blocks the live claim and is never replaced by synthetic evidence.

After mutation prove convergence, GitOps revision, user journey, observability,
no-regression of prior goals, drift absence and cleanup. Roll back immediately
when an abort condition is met.
Never store credentials, kubeconfigs, tokens, cookies, tenant data, private
endpoints or unsanitized operational output in repository evidence.

## Security ordering

Security invariants are implemented with every slice: fail-closed authorization,
least privilege, secret safety, dependency scanning and negative tests. The broad
adversarial security, privacy, compliance and supply-chain review is deliberately
the last goal on the CloudRING 1.0 dependency path, after complete 1.0
functionality exists, followed by fixes and full regression. Each post-1.0 track
must likewise end in its own broad review, fixes and regression before promotion.
