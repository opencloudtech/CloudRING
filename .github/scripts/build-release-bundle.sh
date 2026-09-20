#!/usr/bin/env bash
set -euo pipefail
umask 022

# Run only from a clean checkout. Temporary build outputs stay outside Git so
# embedded VCS metadata describes the accepted source without a dirty flag.
if [[ -n "$(git status --porcelain)" ]]; then
  echo "release bundle requires a clean checkout" >&2
  exit 1
fi
if [[ $# != 1 || -z "$1" ]]; then
  echo "usage: build-release-bundle.sh OUTPUT_DIRECTORY" >&2
  exit 2
fi
if [[ -e "$1" ]]; then
  echo "release output directory already exists" >&2
  exit 1
fi
export GOOS=linux GOARCH=amd64 CGO_ENABLED=0
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
source_sha="$(git rev-parse HEAD)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

for attempt in 1 2; do
  export GOCACHE="${work}/go-cache-${attempt}"
  root="${work}/attempt-${attempt}/cloudring-linux-amd64"
  source_tree="${work}/source-${attempt}"
  bash .github/scripts/checkout-release-source.sh "${source_sha}" "${source_tree}"
  (
  cd "${source_tree}"
  mkdir -p "${root}/bin"
  while IFS= read -r command_dir; do
    command_name="$(basename "${command_dir}")"
    go build -mod=readonly -trimpath -buildvcs=true \
      -ldflags='-buildid=' \
      -o "${root}/bin/${command_name}" "./${command_dir}"
  done < <(find cmd -mindepth 1 -maxdepth 1 -type d -print | LC_ALL=C sort)
  cp LICENSE NOTICE "${root}/"
  go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0 \
    mod -json -test -licenses -noserial -notimestamp \
    -output "${work}/raw-sbom-${attempt}.json" .
  # A release tag added after the main build must not change the same source's
  # identity. Preserve dependency versions and replace every root graph ref.
  jq -S --arg source_sha "${source_sha}" \
    -f .github/scripts/normalize-release-sbom.jq \
    "${work}/raw-sbom-${attempt}.json" >"${root}/cloudring-sbom.cdx.json"
  # The pinned attestation action requires a serial number. UUIDv5 binds it to
  # the normalized document content, without random or wall-clock inputs.
  serial_number="$(python3 - "${root}/cloudring-sbom.cdx.json" <<'PY'
import hashlib
import pathlib
import sys
import uuid

digest = hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
print(uuid.uuid5(uuid.NAMESPACE_URL,
    "https://github.com/opencloudtech/CloudRING/sbom/" + digest).urn)
PY
  )"
  jq -S --arg serial_number "${serial_number}" '.serialNumber = $serial_number' \
    "${root}/cloudring-sbom.cdx.json" >"${work}/serial-sbom-${attempt}.json"
  mv "${work}/serial-sbom-${attempt}.json" "${root}/cloudring-sbom.cdx.json"
  jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.6" and
    (.components | length) >= 1 and
    (.serialNumber | test("^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")) and
    (.metadata | has("timestamp") | not)' \
    "${root}/cloudring-sbom.cdx.json" >/dev/null
  chmod 0755 "${root}" "${root}/bin" "${root}"/bin/*
  chmod 0644 "${root}/LICENSE" "${root}/NOTICE" "${root}/cloudring-sbom.cdx.json"
  )
  tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 \
    --numeric-owner -C "${work}/attempt-${attempt}" -cf - cloudring-linux-amd64 \
    | gzip -n >"${work}/bundle-${attempt}.tar.gz"
done
cmp "${work}/bundle-1.tar.gz" "${work}/bundle-2.tar.gz"
bash .github/scripts/check-release-binaries.sh \
  "${work}/attempt-1/cloudring-linux-amd64/bin/"*
mkdir -p "$1"
cp "${work}/bundle-1.tar.gz" "$1/cloudring-linux-amd64.tar.gz"
cp "${work}/attempt-1/cloudring-linux-amd64/cloudring-sbom.cdx.json" "$1/"
# The client streams this exact Linux executable to an owned guest. Its bytes
# are already covered by the independently reproduced and scanned bundle.
cp "${work}/attempt-1/cloudring-linux-amd64/bin/cloudring" "$1/cloudring-linux-amd64"
(
  cd "$1"
  sha256sum cloudring-linux-amd64.tar.gz cloudring-linux-amd64 cloudring-sbom.cdx.json > SHA256SUMS
)
