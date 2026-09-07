# Publish and verify a retained release

Publish from an accepted protected `main` commit. A green pull request alone is
not a release: verify the post-merge required checks on that exact commit and
the successful `release-provenance` run. Billing failures, missing runners,
failed provenance, and incomplete builds leave the release unpublished.

The workflow independently builds the Linux command bundle and its SBOM twice
with separate Go build caches. The SBOM omits volatile serial/timestamp fields
and binds its main module identity and graph references to the source commit,
independent of Git tags. The archive uses fixed modes, the commit timestamp,
fixed owners, sorted paths and a gzip
header without local filename/time. A byte mismatch fails before attestation.
The recovery worker separately proves binary and OCI subject reproducibility.
Both workflows build their executables before creating in-tree output so VCS
metadata does not acquire a dirty flag from the build itself.

Each build uses a separate shallow checkout of the exact accepted commit,
without tags. This preserves embedded VCS SHA/time while keeping Go's main
module version independent of tags added after the main build. Reproduce with
the exact Go toolchain pinned in the workflow, Linux/amd64 target and GNU tar;
using a different compiler is a different build input.

## Repository prerequisites

An administrator enables release immutability and protects `refs/tags/v*`
against deletion and non-fast-forward updates before publishing. Tag creation
is restricted to the release maintainer. No workflow receives an administrator
credential. Check the existing policy before changing it; do not replace
unrelated repository rules.

The recovery-worker package must allow anonymous pulls. Its public source
repository does not automatically make the GHCR package public. The workflow
verifies the exact OCI digest with an empty Docker credential directory;
private visibility fails this check. Changing an organization-wide package
policy requires authority for that broader setting, beyond one release.

Use the authenticated GitHub CLI to inspect the current protection, required
contexts and immutability setting:

```sh
gh api repos/opencloudtech/CloudRING/branches/main/protection
gh api repos/opencloudtech/CloudRING/rulesets
gh api repos/opencloudtech/CloudRING/immutable-releases
```

The last response must have `enabled: true`. This endpoint requires
administrator read permission, which a normal Actions job does not have.
Enabling it is an administrator operation; do not add a personal token to CI
to work around that boundary.

## Prepare all assets before publication

Choose the accepted source SHA, its successful workflow run ID and a new
version tag. Use a prerelease tag for an incomplete platform capability; the
release notes state the actual supported slice and remaining limitations.
The operator checks those three concrete values before running the sequence.

1. Inspect `gh run view RUN_ID --repo opencloudtech/CloudRING` and the current
   check runs for the accepted SHA. Every configured required check must pass
   on that SHA, including post-merge contribution checks. Confirm the source
   commit is on protected main and its tree is the reviewed candidate.
2. Download exactly that run's `cloudring-linux-amd64` and
   `cloudring-etcd-recovery-worker-release-evidence` artifacts with
   `gh run download RUN_ID --repo opencloudtech/CloudRING --name ARTIFACT_NAME
   --dir NEW_EMPTY_DIRECTORY`. Never select the latest run implicitly.
3. In the bundle directory, run `sha256sum --check SHA256SUMS`. Verify the
   bundle's provenance and CycloneDX SBOM attestations with
   two separate `gh attestation verify cloudring-linux-amd64.tar.gz` calls,
   each with `--repo opencloudtech/CloudRING --source-digest ACCEPTED_SHA
   --signer-workflow opencloudtech/CloudRING/.github/workflows/release-provenance.yml`.
   Use `--predicate-type https://slsa.dev/provenance/v1` for provenance and
   `--predicate-type https://cyclonedx.org/bom` for the SBOM. Inspect the
   returned source SHA, guarded workflow and selected run identity. Verify
   SLSA provenance for the worker identity/component-SBOM files, then verify
   both SLSA and CycloneDX predicates for the published OCI digest from the
   same run with those source/workflow constraints. The identity's source SHA
   must match the accepted SHA; an older worker image is not this release.
4. Create an annotated tag on the exact accepted commit and push only that
   new tag through the configured protection. Read back its peeled SHA.
   Never move or reuse an existing version tag. The tag-triggered build may
   run, but assets selected for this publication stay bound to the already
   verified exact run and accepted commit.
5. Create a **draft** GitHub release with `gh release create TAG --repo
   opencloudtech/CloudRING --verify-tag --draft --prerelease --latest=false
   --notes-file RELEASE_NOTES`. Upload the bundle, SBOM, checksums, worker
   identity, component SBOM and image SBOM using `gh release upload TAG FILES
   --repo opencloudtech/CloudRING`. Use an explicit reviewed file list, not an
   entire working directory. Also retain downloaded build-attestation bundles
   when offline verification is required.
6. Read back the draft asset list and download its assets into another empty
   directory. Compare every file hash with the selected run's originals,
   check the tag's accepted SHA again and verify the notes describe only the
   delivered capability. A partial upload leaves a draft; do not publish it.
7. Publish with `gh release edit TAG --repo opencloudtech/CloudRING
   --draft=false`. Then require the Releases API to report `immutable: true`,
   run `gh release verify TAG --repo opencloudtech/CloudRING` and
   `gh release verify-asset TAG FILE --repo opencloudtech/CloudRING` for each
   retained asset. Download the public release from a fresh environment and
   repeat verification and the applicable executable smoke.

If publication has an uncertain result, read the release before retrying.
When it is already immutable, verify its exact tag/assets and finish; do not
attempt replacement uploads. A conflicting draft or immutable release is a
release identity conflict, not permission to overwrite another result.

The versioned release assets survive expiration of the 30-day Actions artifact
copies. GitHub locks published immutable assets and their tag and provides a
separate release attestation. Build provenance establishes how the binary was
built; release attestation establishes which assets belong to that release.
Installation, runtime behavior and restore require their separate acceptance
evidence before any deployment capability can be claimed.

See GitHub's [immutable release contract](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
and [release asset verification](https://cli.github.com/manual/gh_release_verify-asset).
