# Roadmap verification matrix

This file turns the terminal roadmap goals into executable QA contracts. Angle-
bracket values are not loose placeholders: the matching `roadmap/state/GNN.json`
must resolve them to exact accepted SHAs, immutable artifact digests, target IDs,
evidence paths and freshness windows before a command runs. A command surface
missing when its owning goal starts is an implementation blocker, not an excuse
to substitute prose or synthetic evidence.

## Common release checks

| Check | Command or authority | Expected machine result |
| --- | --- | --- |
| Roadmap graph and requirements | `go run ./cmd/cloudring-roadmap verify --root ./roadmap` | `cloudring_roadmap_verified goals=28 requirements=28`; the graph, requirement ownership and 1.0/post-1.0 boundary are valid |
| Go correctness | `go test ./...` and `go test -race ./...` | exit 0 on the exact accepted public source SHA |
| Static analysis | `go vet ./...` | exit 0 on the exact accepted public source SHA |
| Source safety | `go run ./cmd/cloudring-sourcecheck scan --scope changed` | exit 0, no finding and no secret/private-source output |
| Protected delivery | Hosted required-check readback for each exact main SHA | every required check terminal-success; no skipped/bypassed check |
| Downstream pins | `git ls-tree <accepted-downstream-sha> cloudring_core` | both consumer mains point to the same accepted public commit |
| Hub regression | `go run ./cmd/cloudringctl verify alpha-live --hub-url https://hub.cloudring.org/ --api-health-url https://api.cloudring.org/healthz --evidence <sanitized-evidence>` | exit 0; Hub HTTP 200, API `status=ready`, exact GitOps revision and cumulative journeys green |

## G00-G23 executable goal contracts

The command shown in each row is a **required public interface**, not a claim
that it exists in the current tree. Before a goal may change from `not_started`,
public OSS must implement and test that exact stable interface (or version the
row and requirement first). If the command is absent, unstable, or cannot
resolve the goal state, the goal is `blocked`; operators may not replace it with
an ad hoc script, prose review, fixture-only result, or a downstream-only tool.

Every invocation consumes `roadmap/state/GNN.json`. That state must resolve all
angle-bracket values to exact public, maintained-reference and independent-
downstream revisions and pins;
immutable artifact and release-manifest digests; deployment fingerprints and
GitOps revisions; protected evidence locators; freshness/retention; rollback;
and cleanup. The standard success JSON is
`{"goal":"GNN","requirement":"CR-GNN-*","verdict":"pass","exactTupleBound":true,"cleanup":"pass"}`
plus the goal fields below. Missing, stale, mismatched or unresolved input must
return non-zero and `verdict=blocked`; a negative fixture must return non-zero
with the exact rejected field.

“Ordered acceptance” means: OSS clean-room passes first; the maintained reference
deployment passes at an exact pin of that public SHA; an independent downstream
passes at the same public SHA without access to non-public reference assets; then
the public reference endpoint passes at its exact accepted GitOps revision. Only
that order can set the state to `delivered`. “Cumulative”
means the common release checks and every prior delivered goal's signed terminal
journeys are rerun against the new tuple, with the receipt bound through
`predecessorRegression`.

| Goal | Required public command/tool surface before start | State-resolved goal inputs | Expected machine result in addition to the standard envelope | OSS -> reference -> downstream acceptance | Cumulative regression |
| --- | --- | --- | --- | --- | --- |
| G00 | `go run ./cmd/cloudringctl verify goal --goal G00 --state ./roadmap/state/G00.json --output json` | Remote mains, protected checks, exact pins, worktree/WIP ledger, issue map, source-boundary report, SafePush receipts and hub baseline | `truthfulBaseline=verified`, `sourceBoundary=verified`, `protectedDelivery=verified`, `hubBaseline=verified`; invalid signed-receipt candidate is rejected | Ordered acceptance; Provider SafePush positive and negative qualification and hub pre/post baseline are mandatory | Common checks at the accepted baseline; no predecessor waiver |
| G01 | `go run ./cmd/cloudringctl verify goal --goal G01 --state ./roadmap/state/G01.json --output json` | Pinned toolchain/profile, clean-room fingerprint, signed artifacts, isolated target, create/status/destroy and residue evidence | `devInstall=verified`, `idempotency=verified`, `productionShortcuts=rejected`, `destroyResidue=zero` | Ordered acceptance; each repository runs create/status/destroy and hub uses an isolated non-customer scope | Common + signed G00 receipt; destroy/recreate terminal journey reruns |
| G02 | `go run ./cmd/cloudringctl verify goal --goal G02 --state ./roadmap/state/G02.json --output json` | Site profile, topology/failure domains, protected-input attestations, signed adjacent candidates, off-cell backup target and side-by-side cutover/rollback scope | `haInstall=verified`, `emptyCatalog=verified`, `backupRestore=verified`, `upgradeRollback=verified`, `singleReplicaLoss=verified` | Ordered acceptance; clean-room install precedes downstream plans, then reversible side-by-side hub cutover | Common + G00-G01 receipts; install, restore, rotation, upgrade/rollback and G01 shortcut rejection rerun |
| G03 | `go run ./cmd/cloudringctl verify goal --goal G03 --state ./roadmap/state/G03.json --output json` | Versioned schemas/clients, database migration pair, operation IDs, concurrency/load profile and crash/failover actions | `durableKernel=verified`, `exactlyOnceOutcome=verified`, `auditLinkage=verified`, `databaseFailover=verified` | Ordered acceptance; both downstreams use the public kernel unchanged and hub runs crash/failover/load proof | Common + G00-G02 receipts; all accepted resource/operation/audit journeys rerun after failover |
| G04 | `go run ./cmd/cloudringctl verify goal --goal G04 --state ./roadmap/state/G04.json --output json` | Built-in identity and external OIDC/directory profiles, key revisions, account/session fixtures, rotation/revocation/recovery actions and privacy-safe audit | `identityLifecycle=verified`, `federation=verified`, `revocation=verified`, `keyRotation=verified`, `hiddenUntilAuthenticated=verified` | Ordered acceptance; public built-in and external-source conformance precede downstream bindings and live hub lifecycle | Common + G00-G03 receipts; login, refresh, logout, recovery and denial journeys rerun |
| G05 | `go run ./cmd/cloudringctl verify goal --goal G05 --state ./roadmap/state/G05.json --output json` | Policy revision, hierarchy/role fixtures, human/workload/support identities, stale-policy and replica/node/database failure plan, immutable-audit evidence | `iam=verified`, `crossTenantDenial=verified`, `stalePolicyDenied=verified`, `workloadRotation=verified`, `auditContinuity=verified` | Ordered acceptance; identical evaluator/enforcement runs at every surface, then protected hub identities run the full allow/deny matrix | Common + G00-G04 receipts; continuous allow/deny/explanation/audit probes rerun through every declared failure |
| G06 | `go run ./cmd/cloudringctl verify goal --goal G06 --state ./roadmap/state/G06.json --output json` | Adapter revisions, inventory snapshots, adoption/ownership fixtures, mutation plans, receipts, rate-limit/outage and ambiguous-outcome actions | `inventory=verified`, `adoption=verified`, `mutationExecution=verified`, `drift=verified`, `ambiguousOutcomeReconciled=verified` | Ordered acceptance; an independent downstream proves its adapter without access to non-public reference assets before the reference deployment executes bounded adoption/mutation | Common + G00-G05 receipts; discover/adopt/plan/apply/rollback/reconcile and tenant isolation rerun |
| G07 | `go run ./cmd/cloudringctl verify goal --goal G07 --state ./roadmap/state/G07.json --output json` | OCS schema/SDK/artifact digests, positive/negative fixtures, runtime-consumer matrix and independently built package | `ocsRC=verified`, `schemaParity=verified`, `runtimeConformance=verified`, `independentPackage=verified` | Ordered acceptance; one canonical OSS validator is used unchanged by both downstreams and the hub runtime | Common + G00-G06 receipts; every positive fixture passes and every negative fixture fails on its exact field |
| G08 | `go run ./cmd/cloudringctl verify goal --goal G08 --state ./roadmap/state/G08.json --output json` | Publisher identity/eligibility revision, immutable package and portal artifacts, moderation policy, capability declarations and rollout/rollback/removal plan | `registry=verified`, `moderation=verified`, `sandbox=verified`, `rolloutRollback=verified`, `commercialEligibilityBound=verified` | Ordered acceptance; independent Provider moderation succeeds before hub approve/install/expose/upgrade/disable/remove | Common + G00-G07 receipts; unrelated products and empty-provider core remain green through rollback/removal |
| G09 | `go run ./cmd/cloudringctl verify goal --goal G09 --state ./roadmap/state/G09.json --output json` | Offer/subscription revisions, quota/capacity policy, reservation profile, lifecycle requests and retry/crash/outage/restore actions | `lifecycle=verified`, `quotaBalanced=verified`, `capacityBalanced=verified`, `duplicateResources=zero`, `replaySafe=verified` | Ordered acceptance; downstream policy is configuration only and hub completes real request-to-terminal-state journeys | Common + G00-G08 receipts; retry/cancel/fail/restore/concurrency journeys preserve resource and reservation balance |
| G10 | `go run ./cmd/cloudringctl verify goal --goal G10 --state ./roadmap/state/G10.json --output json` | Meter/tariff/tax/currency revisions, usage/correction fixtures, publisher-share/commission policy, ledger/invoice/payout adapter inputs and backpressure profile | `billing=verified`, `ledgerBalanced=verified`, `invoiceLineage=verified`, `corrections=verified`, `payoutLiability=verified` | Ordered acceptance; public exact-math engine precedes jurisdictional adapters, then hub rates real accepted usage | Common + G00-G09 receipts; duplicate/late/corrected usage and zero-product operation rerun with balanced ledgers |
| G11 | `go run ./cmd/cloudringctl verify goal --goal G11 --state ./roadmap/state/G11.json --output json` | Canonical action/journey definitions, API/CLI/portal/agent clients, accessibility profile, identity scopes and failure fixtures | `semanticParity=verified`, `apiOnlyOperable=verified`, `accessibility=verified`, `agentAttribution=verified`, `uiOnlyCapabilities=zero` | Ordered acceptance; Provider proves API-only operation before hub proves equivalent human and agent journeys | Common + G00-G10 receipts; authorization, validation, operation identity and audit results match across all clients |
| G12 | `go run ./cmd/cloudringctl verify goal --goal G12 --state ./roadmap/state/G12.json --output json` | Network package/backend revisions, IP/DNS/TLS profile, tenant topology, quota/usage policy and gateway/node/family failure actions | `networkProduct=verified`, `dualStack=verified`, `tenantIsolation=verified`, `billingChain=verified`, `directOriginFailover=verified` | Ordered acceptance; independent Provider backend conformance precedes the complete hub catalog-to-invoice network journey | Common + G00-G11 receipts; direct IPv4/IPv6, DNS/TLS, policy, rollback and removal rerun without CDN masking |
| G13 | `go run ./cmd/cloudringctl verify goal --goal G13 --state ./roadmap/state/G13.json --output json` | Volume package, CSI/snapshot versions, failure-domain topology, data digests, encryption/attachment/resize policy and restore actions | `volumeProduct=verified`, `snapshotRestore=verified`, `failureDomain=verified`, `dataDigestMatch=verified`, `cleanupPolicy=verified` | Ordered acceptance; Provider proves supported CSI/backend topology before hub runs lifecycle, failure and isolated restore | Common + G00-G12 receipts; attach/resize/snapshot/restore/node-loss/delete journeys and billing rerun |
| G14 | `go run ./cmd/cloudringctl verify goal --goal G14 --state ./roadmap/state/G14.json --output json` | Image/OCI artifact digests, signatures/SBOM/provenance, architecture/firmware/format matrix, scanner policy and retention/share fixtures | `artifactProduct=verified`, `provenance=verified`, `bootCompatibility=verified`, `scanIsolation=verified`, `portableExport=verified` | Ordered acceptance; public boot harness and conformant registry round-trip precede downstream bindings and hub lifecycle | Common + G00-G13 receipts; import/push/scan/share/replicate/delete and negative provenance journeys rerun |
| G15 | `go run ./cmd/cloudringctl verify goal --goal G15 --state ./roadmap/state/G15.json --output json` | Compute package/KubeVirt revisions, Network/Volume/Image entitlements, workload/data probes, migration prerequisites and node/management failure actions | `computeProduct=verified`, `dependencyEntitlements=verified`, `vmContinuity=verified`, `migrationOrColdRecovery=verified`, `billingChain=verified` | Ordered acceptance; Provider validates the same OCS compute path before hub creates and removes representative VMs | Common + G00-G14 receipts; boot, access, resize, snapshot, migrate/recover, node-loss and invoice journeys rerun |
| G16 | `go run ./cmd/cloudringctl verify goal --goal G16 --state ./roadmap/state/G16.json --output json` | Managed-cluster package, Cluster API/bootstrap revisions, version-skew/add-on matrix, workload/data probes, access rotation and backup target | `managedKubernetes=verified`, `bootstrap=verified`, `versionSkew=verified`, `workloadContinuity=verified`, `isolatedRestore=verified` | Ordered acceptance; an independent downstream installs via its adapter without non-public reference files before the reference deployment exercises a complete tenant cluster | Common + G00-G15 receipts; create/access/scale/upgrade/fail/restore/delete and cross-tenant denial rerun |
| G17 | `go run ./cmd/cloudringctl verify goal --goal G17 --state ./roadmap/state/G17.json --output json` | Object package/backend revisions, local/remote endpoint profiles, object digests, credential/encryption/retention policy and storage/gateway failure actions | `objectProduct=verified`, `dataDurability=verified`, `retentionDenial=verified`, `credentialRotation=verified`, `remoteAdapter=verified` | Ordered acceptance; Provider runs local and remote adapter conformance before hub runs real versioned-object lifecycle | Common + G00-G16 receipts; put/get/list/delete, node loss, isolated restore, billing and retention cleanup rerun |
| G18 | `go run ./cmd/cloudringctl verify goal --goal G18 --state ./roadmap/state/G18.json --output json` | Backup package/adapters, declared data-class inventory, policies/RPO/RTO, off-cell immutable target, representative digests and interruption/restore/cleanup actions | `backupProduct=verified`, `offCellCopy=verified`, `isolatedRestore=verified`, `immutability=verified`, `rpoRto=verified` | Ordered acceptance; each downstream supplies only its target binding, then the hub restores representative product data into isolation | Common + G00-G17 receipts; partial/duplicate/interrupted backup, cross-tenant denial, restore validation and cleanup rerun |
| G19 | `go run ./cmd/cloudringctl verify goal --goal G19 --state ./roadmap/state/G19.json --output json` | Access package, target/method matrix, approval policy, issuer/trust revisions, expiry/revocation actions and recording-retention evidence | `controlledAccess=verified`, `approval=verified`, `expiry=verified`, `revocation=verified`, `noSharedAdminCredential=verified` | Ordered acceptance; Provider bastion/console bindings pass public semantics before bounded hub sessions run against test resources | Common + G00-G18 receipts; approve/use/expire/revoke/emergency/issuer-failure/restore journeys rerun |
| G20 | `go run ./cmd/cloudringctl verify goal --goal G20 --state ./roadmap/state/G20.json --output json` | Support package, entitlement/SLA revisions, case resources, external-route failure plan, redacted bundle manifest and consent/retention/access inputs | `supportProduct=verified`, `slaClock=verified`, `bundleSourceSafe=verified`, `routingOutageDurable=verified`, `accessBounded=verified` | Ordered acceptance; downstream routing/retention is configuration only, then hub completes an entitled case in an isolated tenant | Common + G00-G19 receipts; consent, bundle, bounded access, escalation, restore and retention journeys rerun |
| G21 | `go run ./cmd/cloudringctl verify goal --goal G21 --state ./roadmap/state/G21.json --output json` | Selected external system ADR/profile, two adapter revisions, broker credentials, rate-limit/outage/ambiguous-side-effect actions and usage/cost inputs | `externalProduct=verified`, `adapterReplaceability=verified`, `ambiguousOutcomeReconciled=verified`, `credentialRotation=verified`, `billingLineage=verified` | Ordered acceptance; independent Provider adapter passes before hub runs and cleans the real remote integration | Common + G00-G20 receipts; discover/adopt/provision/hold/resize/deprovision/reconnect/replace-adapter journeys rerun |
| G22 | `go run ./cmd/cloudringctl verify goal --goal G22 --state ./roadmap/state/G22.json --output json` | Incident set, SLO/alert/runbook inventory, rotation and maintenance plans, capacity profile, SafePush recovery inputs and 14-day operator measurement | `oneEngineerOps=verified`, `incidentSet=verified`, `rotation=verified`, `safepushRecovery=verified`, `toilBudget=verified` | Ordered acceptance; independent Provider operator walkthrough precedes bounded hub failure/repair exercises | Common + G00-G21 receipts; all maintenance, overload, restore rehearsal and diagnostic/repair journeys rerun |
| G23 | `go run ./cmd/cloudringctl verify goal --goal G23 --state ./roadmap/state/G23.json --output json` | Signed N-1/N artifacts, version/migration matrix, representative live resources/usage, backup barrier, one-server/component failure actions, probes and rollback boundaries | `upgradeContinuity=verified`, `singleServerLoss=verified`, `rpoRto=verified`, `acceptedWorkLoss=zero`, `billingValidity=verified` | Ordered acceptance; Provider completes the non-destructive campaign, then hub executes the approved integrated mutation/failure campaign | Common + signed G00-G22 receipts; every prior terminal journey reruns after each abort, rollback, restore and recovery |

## G24 portable-provider certification

Prerequisites: G23 delivered, two isolated downstream checkouts, an approved
independent-site environment, protected inventory, off-cell backup target and an
exact live mutation envelope.

1. Run the common checks in the public, OpenCloudTech consumer and independent
   provider consumer repositories.
2. Run `go run ./cmd/cloudringctl verify production-ovh` against the accepted
   OpenCloudTech source. Expected: exit 0 and all structural/live-applicable
   checks ready without private implementation in public core.
3. Run the Provider SafePush Stage 9 pipeline on its exact main. Expected: a
   verified signed receipt binding provider main, public pin, protected inputs
   and all required jobs; no fixture-only qualification.
4. Execute the stable install, backup/restore, signed N-1-to-N upgrade/rollback,
   one-server-loss and cleanup commands delivered by G02/G22/G23 on the
   independent site. Expected state fields: `install=verified`,
   `restore=verified`, `upgradeContinuity=verified`, `singleServerLoss=verified`,
   `cleanup=verified`, with RPO/RTO and continuity measurements inside policy.
5. Build and operate one independently owned OCS product using released public
   SDK/artifacts only. Expected: conformance, lifecycle, billing-policy, support,
   upgrade and removal receipts verify with no non-public reference dependency.

## G27 final security, compliance and CloudRING 1.0 release

Prerequisites: G00-G24 delivered, feature freeze, immutable candidate artifacts,
fresh hub and independent-provider baselines, and a complete finding ledger.

1. Run all common checks plus the repository's deep security, fuzz, dependency,
   provenance, licence, IaC and boundary jobs on the immutable candidate.
2. Run `go run ./cmd/cloudringctl iteration gate --report <sanitized-report>`.
   Expected: exit 0, every G00-G24 requirement result `accepted`, no unresolved
   release blocker, exact public/consumer pins, fresh evidence and
   `mutationAllowed=true`.
3. Run continuous login/session, IAM allow/deny, lifecycle operation, usage
   ingest/rating/ledger/invoice-read and audit probes during one-server loss and
   a signed N-1-to-N upgrade. Expected: zero release-attributable eligible-request
   failures, lost/duplicate accepted work, authorization fail-open, unbalanced
   ledger or invalid invoice.
4. Re-run Network, Volume, Image, VM and the real remote/API-only reference
   product through the same canonical OCS validator, runtime conformance and
   upgrade suite. Expected: all positive fixtures/products pass and every
   negative fixture fails on its exact machine-readable field.
5. Verify signed release tag, SBOM, provenance, compatibility/support matrix and
   clean-clone installation. Expected terminal verdict:
   `cloudring1_0=release_approved`; any accepted risk outside the published policy
   or any missing proof yields `release_blocked`.

## Post-1.0 G25 and G26

G25 and G26 cannot satisfy or block G27. Before either changes to `in_progress`,
it must add and test a stable `cloudringctl verify` command whose JSON binds the
exact standalone 1.0 base, target topology, workload/measurement profile,
failure/partition actions, rollback and cleanup. G25 must prove independent cell
and real-region behavior. G26 must prove opt-in bilateral trust,
partition/reconciliation, local autonomy and that removing any directory,
coordinator, provider or trust relationship cannot disable standalone providers
or unrelated peers. Each track ends with its own broad security review, fixes and
full regression before release promotion.

### G26 private-to-public peak-capacity terminal journey

Run the G26 federation verifier against two independently administered providers
and a capacity-constrained private workload. Its terminal JSON must bind the
exact standalone 1.0 base and both provider SHAs/trust revisions; immutable quote
and bilateral-consent IDs; residency, identity/IAM, quota/capacity and cost-policy
decisions; remote reservation and lifecycle operations; accepted usage,
reconciliation and adapter-ready settlement totals; injected failure actions,
compensating rollback, drain/deprovision and cleanup receipts. Expected:
`privatePublicBurst=verified`, every accepted operation is applied exactly once,
the financial ledgers balance, every rejected/failed phase leaves no unauthorized
resource or charge, and the private provider plus unrelated peers remain usable.
