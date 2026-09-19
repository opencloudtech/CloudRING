#!/usr/bin/env bash
set -euo pipefail
umask 022

# Only the protected release job invokes this publisher. Inputs have already
# passed independent command builds and the Canonical signature/hash check.
source_date_epoch="$(git show -s --format=%ct HEAD)"
test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"
for kind in runtime guest; do
  case "${kind}" in
    runtime) containerfile='build/development/Runtime.Containerfile' ;;
    guest) containerfile='build/development/Guest.Containerfile' ;;
    *) exit 1 ;;
  esac
  image="ghcr.io/opencloudtech/cloudring-development-${kind}"
  for attempt in 1 2; do
    archive="${RUNNER_TEMP}/development-${kind}-${attempt}.tar"
    docker buildx build \
      --file "${containerfile}" --platform linux/amd64 --no-cache \
      --provenance=false --sbom=false \
      --output "type=oci,dest=${archive},rewrite-timestamp=true" \
      --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}" \
      --build-arg "SOURCE_REVISION=${GITHUB_SHA}" \
      .
    tar --extract --to-stdout --file "${archive}" index.json | \
      jq -er '[.manifests[] |
        select(.platform.os == "linux" and .platform.architecture == "amd64") |
        .digest] | select(length == 1) | .[0] |
        select(test("^sha256:[0-9a-f]{64}$"))' \
        > "${RUNNER_TEMP}/development-${kind}-${attempt}.subject"
  done
  cmp "${RUNNER_TEMP}/development-${kind}-1.subject" "${RUNNER_TEMP}/development-${kind}-2.subject"
  subject_digest="$(<"${RUNNER_TEMP}/development-${kind}-1.subject")"
  if [[ "${kind}" == runtime ]]; then
    "${RUNNER_TEMP}/development-syft" scan \
      "oci-archive:${RUNNER_TEMP}/development-runtime-1.tar" \
      -o cyclonedx-json=dist/development-runtime.cdx.json
    jq -e '.bomFormat == "CycloneDX" and (.components | length) >= 1' \
      dist/development-runtime.cdx.json >/dev/null
  fi
  docker buildx build \
    --file "${containerfile}" --platform linux/amd64 --no-cache \
    --provenance=false --sbom=false \
    --output "type=registry,name=${image}:sha-${GITHUB_SHA},push=true,rewrite-timestamp=true,oci-mediatypes=true" \
    --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}" \
    --build-arg "SOURCE_REVISION=${GITHUB_SHA}" \
    --metadata-file "${RUNNER_TEMP}/development-${kind}-published.json" \
    .
  published_digest="$(jq -er '.["containerimage.digest"] |
    select(test("^sha256:[0-9a-f]{64}$"))' "${RUNNER_TEMP}/development-${kind}-published.json")"
  docker buildx imagetools inspect --raw "${image}@${published_digest}" \
    > "${RUNNER_TEMP}/development-${kind}-published-manifest.json"
  published_subject="$(jq -er --arg published_digest "${published_digest}" '
    if .mediaType == "application/vnd.oci.image.index.v1+json" or
       .mediaType == "application/vnd.docker.distribution.manifest.list.v2+json"
    then [.manifests[] |
      select(.platform.os == "linux" and .platform.architecture == "amd64") |
      .digest] | select(length == 1) | .[0]
    else $published_digest end |
    select(test("^sha256:[0-9a-f]{64}$"))' \
    "${RUNNER_TEMP}/development-${kind}-published-manifest.json")"
  test "${published_subject}" = "${subject_digest}"
  jq -n -S \
    --arg source_commit "${GITHUB_SHA}" \
    --argjson source_date_epoch "${source_date_epoch}" \
    --arg image_name "${image}" \
    --arg image_digest "${published_digest}" \
    --arg image_subject_digest "${subject_digest}" '
    {apiVersion: "cloudring.development-image/v1", sourceCommit: $source_commit,
     sourceDateEpoch: $source_date_epoch, buildPlatform: "linux/amd64",
     imageName: $image_name, imageDigest: $image_digest,
     imageSubjectDigest: $image_subject_digest}' \
    > "dist/development-${kind}-image.json"
  printf '%s-digest=%s\n' "${kind}" "${published_digest}" >> "${GITHUB_OUTPUT}"
done
python3 .github/scripts/development-release.py finalize
