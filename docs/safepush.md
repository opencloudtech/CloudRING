# SafePush admission

SafePush checks whether the exact proposed source has completed the full test
policy before a protected branch can change. It belongs in trusted CI and the
hosting platform's admission controls. A local hook is an optional early check;
disabling it must never permit a protected update.

## Implementation and enforcement are separate

`pkg/safepush` provides the check evaluator and a native GitHub CI adapter.
`cloudring-safepush github` reads `.github/safepush.json` from the exact accepted
target commit through the GitHub API, then verifies the current pull request
and its CI runs. It does not read a candidate-supplied success report, execute
candidate code, approve a review, publish a status, merge, or update a ref.

The policy is a complete list of pre-merge workflows and jobs. In particular,
Windows tests are included even when a historical branch rule omitted them.
Excluded workflows must be explicitly listed and must not contain required
pre-merge tests. The release workflow runs after acceptance and is checked
separately as part of release delivery.

Only actual completed-success jobs satisfy the policy. A missing job, an
unexpected job, a duplicate, a skipped or neutral result, an earlier successful
attempt hiding a later failure, an unrelated same-named workflow, or a changed
head/base must block the result. An API failure or incomplete response is not
evidence that there are no failing checks.

The adapter also reads each accepted required workflow blob and checks its
Git object hash before parsing the YAML. A job or step may omit
`continue-on-error` or set it to the literal boolean `false`. Allowed failures
cannot be identified reliably from API conclusions alone. YAML aliases,
anchors, merge keys, duplicate keys and multiple documents are unsupported
and block verification.

The native adapter owns pagination, repository/run/job identity, source
binding, selection of the current attempt and final state readback. The pure
`VerifyChecks` helper checks consistency of those observations; it is not an
authentication or enforcement boundary on its own. Passing a metadata check
also does not prove that a modified test still tests the right behavior. Human
review remains necessary.

GitHub observations require an open, non-draft PR and the current target as
an ancestor of its head. Every selected run must be associated with that exact
PR, head, base and target. These API reads are not atomic with a later merge,
and the run's head and PR association alone do not prove the historical tested
merge commit. Native target freshness and owner review remain required; the
deployment must qualify its event and checkout behavior before activation.

## GitHub deployment contract

For repositories that require pull requests, the organization must require the
SafePush workflow from an immutable accepted CloudRING source commit. A
candidate-owned wrapper calling a reusable workflow is insufficient: the
candidate could delete or replace the wrapper. Requiring only the GitHub
Actions app and a check name also does not identify a particular workflow.

The trusted workflow must check out only its own immutable source, run on a
GitHub-hosted runner, and use read-only contents, Actions, checks and pull
request access. It must not execute candidate scripts or actions, consume
candidate artifacts or shared build caches, or receive publishing credentials.
The CLI takes the current candidate identity from the native event and reads
the accepted policy itself:

```sh
cloudring-safepush github \
  --repository "$TARGET_REPOSITORY" \
  --pr "$PULL_REQUEST_NUMBER" \
  --head "$CANDIDATE_SHA" \
  --base "$ACCEPTED_BASE_SHA" \
  --branch "$TARGET_BRANCH"
```

The job supplies its read-only `GITHUB_TOKEN`. Only pending CI is retried, for
a bounded time. Completed failures, mismatched identity, changed source,
authentication failure and malformed responses stop admission immediately.

Native rules must independently enforce the owner's approval, dismiss stale
reviews and prevent unauthorized review dismissal. Both `main` and `master`
need protection. Test/review bypass identities must be explicit; assigning an
administrator role must not automatically add a SafePush exception. Force
push and deletion controls should remain separate from test/review exceptions.
Existing native code scanning checks remain required alongside SafePush;
generated provider workflows must not be silently relabeled as trusted
repository files.

Keep every underlying required CI check in the native rule as well. An old
successful aggregate cannot revoke itself if a later attempt on the same head
fails after the verifier exits. Activation must test that a later failing
attempt blocks acceptance even when an earlier aggregate was successful.

GitHub's required-workflow rule blocks direct pushes and supports PR and merge
queue events. It must not be presented as accepting arbitrary prechecked direct
pushes. A merge queue needs its own exact merge-group observation contract
before being enabled; a PR-only verifier cannot validate it.

## GitLab deployment contract

The tests must run on qualified nonpersonal Linux CI infrastructure with an
immutable trusted configuration. A candidate-local `.gitlab-ci.yml` include
cannot make a policy mandatory, because another candidate can remove or
override it. Pipeline and approval observations must come from GitLab, not
forwarded variables asserting that every gate passed.

On GitLab Community Edition, successful-pipeline merge settings do not check
direct pushes, and role-based branch permissions cannot isolate one reviewer
when the project inherits other Maintainers and Owners. A green approval job
is also insufficient: the approval can be revoked after the pipeline passes.
Where native enforcement cannot express the policy, a server admission hook
must perform the final current-state decision before the ref changes.

Such a hook must be installed and owned by the GitLab administrator, outside
candidate-controlled files. Its allowlist must scope it to the intended
CloudRING project IDs and protected refs. It must preserve unrestricted
ordinary branch pushes, reject absent/ambiguous/stale CI or review evidence,
verify the exact old/new commit relationship, and support only explicitly
authorized bypass identities. It must not use a personal workstation or
execute candidate code with its admission credentials.

## Activation evidence

Committing these sources or passing local tests does not enable server
enforcement. Record the actual installed immutable revision and re-read the
hosting platform's rules. Use an identity without bypass to verify that an
ordinary branch push succeeds while missing/failed/skipped tests, an
unapproved change, altered CI policy and stale commit evidence cannot advance
`main` or `master`. Verify a real approved all-green change, the intended owner
exception and unchanged out-of-scope repositories. Preserve an explicit
incomplete state until those checks have passed.
