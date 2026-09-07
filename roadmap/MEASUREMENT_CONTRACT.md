# Measurement contract

Claims about availability, zero downtime, scale, one-engineer operation and
developer simplicity are valid only when measured with a versioned profile.

## Common evidence envelope

Every measurement records:

- goal and requirement IDs;
- immutable release/artifact digests and deployed GitOps revision;
- sanitized hardware, topology and software-version profile;
- workload generator and dataset digests;
- start/end clocks in UTC and clock-sync health;
- warm-up, steady-state and recovery windows;
- request/operation counts, exclusions and formulas;
- raw evidence location and sanitized summary hash;
- abort thresholds, cleanup and verifier identity.

Changing a workload, topology, dataset or formula creates a new profile version;
results from different profiles are not silently compared.

## Availability and upgrade

- Monthly availability uses a complete consecutive calendar month and the
  published eligible-request definition. A prerelease soak cannot claim it.
- Goal qualification uses at least 24 continuous hours for the integrated
  management plane and at least the goal-specific failure/upgrade window.
- The 24-hour qualification passes only with at least 99.95% eligible-request
  availability, every profile-specific p99/error threshold green, zero committed
  data loss or invalid billing, and no unresolved release-blocking alert. It is a
  qualification result, not a claim that a calendar-month objective was observed.
- Availability denominator is all eligible synthetic and real test requests;
  excluded planned destructive tests are reported separately, never removed from
  a customer-facing SLO retrospectively.
- Zero-downtime upgrade means zero release-attributable failed eligible requests,
  zero unavailable readiness samples, zero lost accepted operations, zero data or
  billing corruption, and p99 remaining inside the published SLO. Probe interval
  is at most one second for the bounded upgrade campaign.
- Baseline latency/error distribution is measured for at least 30 minutes before
  mutation at the same load. The campaign reports absolute and relative change.

## Reference load profiles

C01 freezes `measurement-profiles.json` before developer delivery; full G00
verifies these acceptance inputs. The profiles cover at least:

- management API mix: reads, lists/watches and durable mutations by multiple
  tenants, including one noisy tenant;
- lifecycle mix: provision/resize/suspend/deprovision with provider latency and
  ambiguous failures;
- usage/billing stream: duplicates, late events, corrections and invoice close;
- portal/CLI/agent journey concurrency;
- each product's data/control path and failure-domain workload.

Each profile publishes p50/p95/p99 latency, throughput, saturation point, error
classes, queue depth, resource use and recovery time. A release has no generic
“high load” claim without these profiles.

Before G00 completes, the profiles also freeze the eligible-request definition,
minimum sample size, exact durable-operation acknowledgement threshold, exclusion
classes and pass formulas. Missing numeric thresholds block later performance or
“quick response” claims.

## Cell scale efficiency

At identical per-cell hardware and SLO, useful capacity means completed eligible
operations or documented product data units per steady-state second while every
latency, error, durability and fairness threshold remains green. The useful
capacity of two independent cells must be at least 1.7 times one-cell capacity
before G25 claims horizontal scale.
The report identifies the first shared bottleneck and reserves at least 30%
headroom at the recommended operating point. Tenant/system fairness and recovery
traffic must pass while one cell is deliberately overloaded.

## Installation and operator toil

- Installation timing starts after the versioned prerequisite validator reports
  green and ends after live acceptance. Waiting for hardware or approvals is
  reported separately.
- Human-attention time counts active terminal/UI, diagnosis and manual-decision
  time; unattended reconciliation does not count. Repeated failed automation does.
- The one-engineer profile is a trained Linux/Kubernetes operator using only
  public docs and shipped tooling, with no author/private chat assistance.
- Healthy-state daily toil is sampled for at least 14 representative days.
- The incident set includes API replica loss, database failover, GitOps drift,
  expired/rotating credential, connector outage, network/storage degradation,
  capacity risk and failed upgrade.

## Developer experience

- The tester is a mid-level developer familiar with one supported language but
  not CloudRING internals.
- Timing starts from a clean machine and empty repository after documented tool
  prerequisites are installed; it ends when the original service passes local
  positive/negative conformance and produces a verified signed package.
- Permitted help is public documentation and ordinary compiler/test errors. No
  private repository, unpublished module, author cache or direct author guidance
  is allowed.
- Report setup time, active development time, conformance failures, documentation
  defects and the exact package digest. The two-hour target is not met by a
  generated unchanged template.

## Frozen qualification inputs

`measurement-profiles.json` version `cloudring-qualification-v1` contains numeric
**acceptance targets, not observed performance**. `roadmapcheck` requires every
listed profile and rejects omitted numeric limits, unsafe windows and weakened
original recovery/human objectives. Concrete test implementations and measured
hardware capacity are delivered by the owning G goal, using these fixed inputs.
A profile cannot pass before its generator, dataset and topology digests and raw
results are present in signed evidence. Changing any input creates a reviewed
new version before running a qualification; a failing run cannot lower targets.

Each statistical run measures at least the common baseline window and its
`minimumSamples` for the explicit `sampleUnit`, whichever takes longer. The
sample unit distinguishes data requests, durable acknowledgements and human
responses from expensive complete lifecycle journeys. The integrated management
campaign additionally uses the full 24-hour qualification window. Report sample
counts by method and tenant; a p50/p95/p99 qualification claim for a named
population requires its minimum sample count, not a few successful trials.

Every supported lifecycle method and declared failure domain additionally needs
at least `minimumLifecycleTrialsPerMethod` complete real trials with success,
retry/restart/failure, denial where applicable, actual backend/data readback and
cleanup. Those numeric completion/recovery bounds are checked on every trial;
three trials never prove statistical p99. The original owning goal may require
more journeys, participants or data classes and still governs acceptance. Report
unique resources, actual provider effects, bytes copied/recovered and retries
separately: policy/read/replayed requests cannot represent create, restore or
upgrade throughput. No simulated backend substitutes for a complete trial.

`concurrency` counts request actors, not a grant of backend resources. Workload
text bounds simultaneous resource stock; provisioning/deletion cycles balance
and resource-dependent actions await real completion. Approved capacity and
ownership still govern every run. Missing capacity is an explicit dependency,
not permission to exceed a site envelope or buy resources.

All control mutations use the common durable-acknowledgement p50/p95/p99 limits,
including profiles whose primary metric measures data or user response. Product
latency thresholds apply to the stated data unit; slower asynchronous work has a
separate numeric completion deadline and a visible durable operation. Read/list
results finish only when the bounded result is available. Report each class and
tenant separately, with qualified percentiles only for sufficient samples. At the offered rate, require every latency and throughput
threshold, the common availability/error formula and bounded resource/queue
limits. Queue depth includes all accepted unfinished work, including retries.

The workload text freezes data sizes, mix, tenant count, denial cases and failure
set. Deterministic generators record the fixed seed and exact content digest;
external datasets additionally bind approved immutable source digests. The
common provider-latency and ambiguity mix exercises delayed or lost responses
around real backend side effects; simulated provider-only runs never prove
product readiness. Reconciliation has its own bounded deadline after recovery.

Measure saturation by increasing the offered rate in the published bounded steps
for at least the specified seconds per step until any SLO fails or the search
ceiling is reached. Stop on an abort threshold; preserve the failure evidence.
Saturation is the first failing rate, with the previous fully green rate reported
as useful capacity. If the ceiling remains green, report only a lower bound.
The recommended rate must reserve at least 30% of measured useful capacity; the
same hardware/topology and every SLO apply to the one-cell/two-cell comparison.
Do not claim a saturation point from an arbitrary fixed load. G25 owns the
post-1.0 two-cell ratio; this numeric input is not a current scale claim.

Record peak and steady-state CPU, memory, queue depth and per-tenant throughput,
p50/p95/p99, all error classes and recovery time. Noisy-tenant tests must preserve
absolute SLOs and the frozen other-tenant relative p99/throughput limits. Abort
on unauthorized success, corruption, lost accepted work, invalid billing,
unbounded queue/resource growth, or the numeric utilization threshold. Cleanup,
rollback and missing-sample checks remain mandatory even after abort.
