#!/usr/bin/env bash
set -euo pipefail
umask 022

# Run after downloading this same workflow run's reproduced command bundle.
# No user input, upstream executable, guest boot or package installation runs.
test ! -e dist/development-inputs
mkdir -p dist/development-inputs
(
  cd dist/release-bundle
  sha256sum --check --strict SHA256SUMS
)
for command in cloudring cloudring-server; do
  tar --extract --gzip --to-stdout \
    --file dist/release-bundle/cloudring-linux-amd64.tar.gz \
    "cloudring-linux-amd64/bin/${command}" > "dist/development-inputs/${command}"
  chmod 0555 "dist/development-inputs/${command}"
  go version -m "dist/development-inputs/${command}" | \
    awk -v sha="${GITHUB_SHA}" '
      $1 == "build" && $2 == "vcs.revision=" sha {revision=1}
      $1 == "build" && $2 == "vcs.modified=false" {clean=1}
      END {exit !(revision && clean)}'
done
cmp dist/release-bundle/cloudring-linux-amd64 dist/development-inputs/cloudring

inputs='build/development/upstream.json'
guest_url="$(jq -er '.guestSource.url' "${inputs}")"
guest_base="${guest_url%/*}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
mkdir -m 0700 "${work}/gnupg"
export GNUPGHOME="${work}/gnupg"
gpg --batch --import build/development/ubuntu-cloud-key.asc
expected_fingerprint="$(jq -er '.guestSource.signerFingerprint' "${inputs}")"
actual_fingerprint="$(gpg --batch --with-colons --list-keys | awk -F: '$1 == "fpr" {print $10; exit}')"
test "${actual_fingerprint}" = "${expected_fingerprint}"
for name in SHA256SUMS SHA256SUMS.gpg ubuntu-24.04-server-cloudimg-amd64.manifest; do
  curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --max-time 120 --output "${work}/${name}" "${guest_base}/${name}"
done
gpg --batch --status-fd 1 --verify "${work}/SHA256SUMS.gpg" "${work}/SHA256SUMS" \
  > "${work}/signature-status"
awk -v fingerprint="${expected_fingerprint}" '
  $1 == "[GNUPG:]" && $2 == "VALIDSIG" {
    for (i=3; i<=NF; i++) if ($i == fingerprint) valid=1
  }
  END {exit !valid}' "${work}/signature-status"
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --max-time 900 --output "${work}/ubuntu-24.04-server-cloudimg-amd64.img" "${guest_url}"
python3 .github/scripts/development-release.py verify-guest "${work}"
cp "${work}/ubuntu-24.04-server-cloudimg-amd64.img" dist/development-inputs/ubuntu.img
cp "${work}/ubuntu-24.04-server-cloudimg-amd64.manifest" dist/development-guest-packages.manifest
cp "${work}/SHA256SUMS" dist/development-ubuntu-SHA256SUMS
cp "${work}/SHA256SUMS.gpg" dist/development-ubuntu-SHA256SUMS.gpg
cp build/development/ubuntu-cloud-key.asc dist/ubuntu-cloud-key.asc
python3 .github/scripts/development-release.py guest-sbom

syft_version='1.49.0'
syft_archive="${work}/syft.tar.gz"
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --max-time 180 --output "${syft_archive}" \
  "https://github.com/anchore/syft/releases/download/v${syft_version}/syft_${syft_version}_linux_amd64.tar.gz"
echo '7aa2f03ee92739cf643279ba3990548b9925d4e22cae13f46831ee62821147fe  '"${syft_archive}" | sha256sum --check --strict
tar --extract --gzip --file "${syft_archive}" --directory "${work}" syft
test "$("${work}/syft" version -o json | jq -r .version)" = "${syft_version}"
install -m 0555 "${work}/syft" "${RUNNER_TEMP}/development-syft"
