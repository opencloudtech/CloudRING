#!/usr/bin/env bash
set -euo pipefail

if (( $# == 0 )); then
  echo "usage: check-release-binaries.sh BINARY..." >&2
  exit 2
fi
for binary in "$@"; do
  if [[ ! -f "${binary}" || -L "${binary}" || ! -s "${binary}" ]]; then
    echo "release input is not a regular nonempty binary: ${binary}" >&2
    exit 1
  fi
done
scanner_dir="$(mktemp -d)"
trap 'rm -rf "${scanner_dir}"' EXIT
# The scanner runs on the build host even when the binary targets Linux.
GOBIN="${scanner_dir}" GOOS="$(go env GOHOSTOS)" GOARCH="$(go env GOHOSTARCH)" \
  go install golang.org/x/vuln/cmd/govulncheck@v1.6.0
for binary in "$@"; do
  printf 'Checking release binary: %s\n' "${binary}"
  "${scanner_dir}/govulncheck" -mode=binary "${binary}"
done
