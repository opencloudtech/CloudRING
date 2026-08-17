# CloudRING CI Checks

Public CI for a clean clone runs these read-only checks on the latest security
patch of the minimum supported Go release (1.25) and runs unit tests again on
the current supported release (1.26):

```bash
go mod download
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go run ./cmd/cloudring-sourcecheck scan --scope full
packages=(./examples/synthetic-service-module/connector-package.json ./reference/synthetic-service/module-package.json ./modules/*/module-package.json)
go run ./cmd/ocsctl validate "${packages[@]}"
go run ./cmd/ocsctl conformance "${packages[@]}"
docker build --file ./reference/synthetic-service/Containerfile --tag cloudring-synthetic-service:ci .
docker run --rm cloudring-synthetic-service:ci --mode=mock-provider --check
```

Enable the tracked local pre-push gate once per clone:

```bash
git config core.hooksPath .githooks
```

The hook rejects unsafe intermediate commits before transport. GitHub
protected-branch rules and the `source-safety` workflow remain authoritative;
local hook configuration is never accepted as merge evidence.

The public CI contract covers these checks:

| Check | Contract |
| --- | --- |
| Go tests | The public module must pass tests on supported minimum/current Go releases, plus race, vet, read-only module graph, and build checks. |
| PostgreSQL integration | The transactional-state CAS, migrations, digest, and concurrent-writer behavior must pass against a real digest-pinned PostgreSQL service with synthetic, non-secret test configuration. |
| Windows | The same unit suite is run on `windows-latest` as a portability signal. Native Windows support is not a release-readiness blocker for the current goal. |
| OCS validation | Every shipped connector package selected by the shared CI package list must pass `go run ./cmd/ocsctl validate`. |
| OCS conformance | The same exact shipped connector packages must pass `go run ./cmd/ocsctl conformance`; validation cannot be green for an artifact that CI omits from conformance. |
| Synthetic reference image | The digest-pinned `Containerfile` must build and its local mock-provider self-check must pass. |
| Source-safety | The Go scanner must approve the complete tree and pre-push commit range, including intermediate commits and reviewed non-text artifacts. |
| Security | CodeQL, govulncheck, gosec, and both current-tree and Git-history secret scans must pass without broad exclusions. Repository gitleaks rules cover password-shaped assignments, XML values, and URL userinfo independently of entropy. |
| Supply chain | Actions must be commit-pinned; workflows must be syntax-checked and must not request unexpected write permissions or PR secrets. The protected-push release workflow builds the Linux CLI bundle plus the digest-pinned etcd recovery worker image, verifies two independent OCI builds have the same Linux AMD64 subject digest, requires the published subject to match, emits separate component-inventory and real image SBOMs, publishes only the immutable GHCR image, creates GitHub/Sigstore attestations, and confirms the published digest is anonymously pullable. |
| License and contribution docs | `LICENSE`, `NOTICE`, `CONTRIBUTING.md`, `SECURITY.md`, `GOVERNANCE.md`, `CLA.md`, `DCO.md`, and `TRADEMARKS.md` must exist in the public root. |
| CLA/DCO | Matching author and co-author sign-offs are checked on pull-request, merge-queue, and protected-branch push ranges. The sign-off records both DCO certification and CLA assent under the published contribution terms. |

The PostgreSQL service is an isolated CI dependency. This does not claim that
a provider database or its backup and failover have been verified live.

This contract does not require live provider credentials, secret environment
variables, network mutation, or live Kubernetes access. Passing it only means
the CloudRING public tree is locally safe to publish and validate; it is not a
production readiness claim.

Reviewed content exceptions remain bound to their exact repository path and
whole-file digest. A recursive gitlink scan may add exactly one canonical
gitlink path segment, and only for inputs whose scanner provenance identifies
the corresponding gitlink index or worktree variant; nested, traversing, or
near-match paths remain blocked.

## SafePush trust boundary

`.github/workflow-policy.json` binds every required workflow to its exact
canonical YAML/JSON semantic surface. The supply-chain job also rejects an
unexpected workflow or job, event/permission expansion, mutable action or
runtime image, credential context, conditional skip, and `continue-on-error`.
Changing a reviewed workflow requires changing its recorded digest in the same
review.

This repository check is defense in depth, not a self-authenticating policy: a
pull request controls the workflow revision that evaluates that pull request.
The server-side trust control for external contributors is protected `main`
with an up-to-date branch, one approving owner review, stale-review dismissal,
last-push approval, required conversations and checks, and no force-push or
branch deletion. The project founder and lead maintainer, `@trukhinyuri`, is
the final acceptance authority. Contributor-authored changes require that
owner review; automated or AI-assisted review does not replace the founder's
decision.

GitHub does not let a pull-request author submit the approval required by the
same branch rule. While the repository has a single founder/administrator, a
founder-authored pull request may therefore use the administrator merge path
after a recorded founder review of the exact head SHA. This narrow owner path
still requires every configured status check to succeed on the current head,
an up-to-date base, resolved conversations, source-safety approval, and a
post-merge `main` verification. It does not authorize direct pushes, skipped
checks, force-pushes, branch deletion, or bypasses for other contributors.
Adding another administrator changes this trust assumption and requires an
explicit governance and branch-protection review before that access is
granted.

## Release provenance

`.github/workflows/release-provenance.yml` is triggered only by pushes to
`main` or `v*` tags, and both jobs additionally require `push`,
`github.ref_protected`, and the exact `main|v*` ref shape. It has no
`workflow_dispatch` or pull-request trigger. A protected tag ruleset is
therefore a prerequisite for version-tag publication. One job builds all
public Go commands for Linux AMD64 with read-only modules and embedded VCS
metadata, packages `LICENSE`, `NOTICE`, and the module CycloneDX SBOM, records
the bundle checksum, and creates GitHub artifact attestations.

The image job independently reproduces the worker binary and two OCI image
layouts, checks their Linux AMD64 subject manifest digests are identical, and
requires the separately pushed registry subject to match that reviewed digest.
The official `etcdutl` 3.6.13 archive, binary, BuildKit, Dockerfile frontend,
Buildx and Syft inputs are immutable-version or content pinned. The job
publishes only `sha-<commit>`, creates a real Syft image-package SBOM plus a
separately named release-component inventory, and emits a canonical
`cloudring.etcd-recovery.image-identity/v1` document binding source commit,
image/index and subject digests, executable hashes, base image, Containerfile
and both SBOM hashes. Image provenance and image SBOM attestations bind the
published digest; component inventory and identity attestations bind their own
files rather than being mislabeled as image SBOMs. Finally the job logs out and
requires an anonymous digest pull.

Job-local `packages`, `id-token`, and `attestations` writes are limited to those
two exact guarded release jobs. The first GHCR package creation may still need
an organization owner to set package visibility to public and confirm
repository permission inheritance; the OCI source label links the package to
this repository, but it does not override organization policy. A failed
anonymous-pull gate is a blocked release, not permission to weaken the gate.

After downloading the bundle from its workflow run, verify the provenance and
SBOM attestation against this repository:

```bash
gh attestation verify cloudring-linux-amd64.tar.gz \
  --repo opencloudtech/CloudRING
```

An attestation binds an artifact to its accepted source and build workflow; it
does not replace vulnerability scanning, code review, release policy, or live
service validation.
