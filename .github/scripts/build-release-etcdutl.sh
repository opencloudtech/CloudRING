#!/usr/bin/env bash
set -euo pipefail
umask 022

# Keep the upstream release source unchanged. Rebuild it with the release Go
# compiler and preserve symbols so govulncheck can inspect the shipped binary.
if [[ $# != 1 || -z "$1" ]]; then
  echo "usage: build-release-etcdutl.sh OUTPUT_DIRECTORY" >&2
  exit 2
fi
if [[ -e "$1" || -L "$1" ]]; then
  echo "etcdutl output directory already exists" >&2
  exit 1
fi

version='3.6.14'
source_commit='fc04cf702b0a46c2fd85547a2be05705b100a496'
source_archive_sha256='c02ebbf6af5f9266f111009fb8d585649a9fcafe5788c200f5a28a7f00d438f0'
source_url="https://codeload.github.com/etcd-io/etcd/tar.gz/${source_commit}"
go_version='go1.26.8'

# Resolve an explicitly selected toolchain once, then disallow automatic
# switching and caller-specific build settings in both independent builds.
go_root="$(go env GOROOT)"
go_bin="${go_root}/bin/go"
test "$("${go_bin}" env GOVERSION)" = "${go_version}"
export GOENV=off GOFLAGS='' GOWORK=off GOTOOLCHAIN=local
export GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0
export GOEXPERIMENT='' GOFIPS140=off GOTELEMETRY=off
export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
export GOPRIVATE='' GONOPROXY='' GONOSUMDB=''

work="$(mktemp -d)"
cleanup() {
  # The Go module cache intentionally makes downloaded module directories
  # read-only. This private temporary tree must still be removed on failure.
  chmod -R u+w "${work}"
  rm -rf "${work}"
}
trap cleanup EXIT
archive="${work}/etcd-source.tar.gz"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "${archive}" "${source_url}"
printf '%s  %s\n' "${source_archive_sha256}" "${archive}" \
  | sha256sum --check --strict

for attempt in 1 2; do
  source_tree="${work}/source-${attempt}"
  mkdir "${source_tree}"
  tar --extract --gzip --file "${archive}" --directory "${source_tree}"
  source_root="${source_tree}/etcd-${source_commit}"
  test -d "${source_root}/etcdutl"
  # The verified source archive binds the complete tree; these checks also
  # prevent a version-label or module-path mismatch during a future pin bump.
  grep -Eq '^[[:space:]]*Version[[:space:]]*=[[:space:]]*"3\.6\.14"$' \
    "${source_root}/api/version/version.go"
  grep -Fxq 'module go.etcd.io/etcd/etcdutl/v3' "${source_root}/etcdutl/go.mod"
  (
    cd "${source_root}/etcdutl"
    GOCACHE="${work}/go-cache-${attempt}" \
    GOMODCACHE="${work}/go-modules-${attempt}" \
      "${go_bin}" build -mod=readonly -trimpath -buildvcs=false \
        -ldflags="-buildid= -X=go.etcd.io/etcd/api/v3/version.GitSHA=${source_commit}" \
        -o "${work}/etcdutl-${attempt}" .
  )
done
cmp "${work}/etcdutl-1" "${work}/etcdutl-2"
binary_sha256="$(sha256sum "${work}/etcdutl-1" | cut -d ' ' -f 1)"

# Outputs remain unpublished until both independent source trees and caches
# produce identical bytes. The source record is deterministic across hosts.
mkdir -p "$(dirname "$1")"
mkdir "$1"
install -m 0555 "${work}/etcdutl-1" "$1/etcdutl"
install -m 0644 "${source_root}/LICENSE" "$1/etcd-LICENSE"
if [[ -f "${source_root}/NOTICE" ]]; then
  install -m 0644 "${source_root}/NOTICE" "$1/etcd-NOTICE"
fi
jq -n -S \
  --arg version "${version}" \
  --arg source_commit "${source_commit}" \
  --arg source_url "${source_url}" \
  --arg source_archive_sha256 "${source_archive_sha256}" \
  --arg go_version "${go_version}" \
  --arg binary_sha256 "${binary_sha256}" '
  {
    schemaVersion: "cloudring-etcdutl-source/v1",
    upstreamVersion: $version,
    sourceCommit: $source_commit,
    sourceArchiveUrl: $source_url,
    sourceArchiveSha256: $source_archive_sha256,
    goVersion: $go_version,
    goos: "linux",
    goarch: "amd64",
    goamd64: "v1",
    cgoEnabled: false,
    symbolsRetained: true,
    independentBuilds: 2,
    reproducible: true,
    binarySha256: $binary_sha256
  }' > "$1/etcdutl-source.json"
chmod 0644 "$1/etcdutl-source.json"
