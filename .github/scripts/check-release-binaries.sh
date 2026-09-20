#!/usr/bin/env bash
set -euo pipefail

# Two-stage vulnerability gate for shipped release binaries.
#
# Stage 1 scans each release binary with `govulncheck -mode=binary`, exactly
# as the previous single-stage gate did. Binary mode can only prove that
# vulnerable symbols are present in the binary; it cannot prove that they
# are reachable from the tool's entry points, so a binary-mode finding alone
# would block an offline CLI on server-only advisories it can never execute.
#
# Stage 2 runs only when stage 1 reports findings. It downloads the same
# pinned upstream etcd source that build-release-etcdutl.sh verified and
# built the binary from, and re-runs govulncheck in source mode on the
# etcdutl main package of that source. govulncheck grounds non-main root
# packages at every exported function, which would invent entry points the
# shipped command never exposes, so the scan targets only the main package
# that `go build .` in the build script links into the binary; its entry
# points (main and init) are the binary's real entry points.
#
# The gate fails only when source mode confirms a reachable finding. A
# binary-mode finding that source mode classifies as not called is printed
# as informational and does not fail the gate. If stage 2 cannot run at all
# (source download, verification, toolchain, or scan failure, including no
# network) the gate fails closed: an unadjudicated finding stays a failure.
#
# govulncheck v1.6.0 exit codes (internal/scan/errors.go): 0 = no findings
# at the requested scan level, 3 = findings at the requested scan level,
# 1 = scanner error, 2 = usage error.

usage() {
  cat >&2 <<'EOF'
usage: check-release-binaries.sh [--etcd-version VERSION
                                  --source-commit COMMIT
                                  --source-archive-sha256 SHA256] BINARY...

The three pin options override the built-in etcd source pin and must be
provided together. With no options the built-in pin is used; it must be
kept in sync with build-release-etcdutl.sh, which builds the binary that
this script adjudicates.
EOF
}

# ANCHOR(etcd-pin): this pin must be bumped together with the identical pin
# block in build-release-etcdutl.sh. That script builds the binary under
# test from this exact source; drifting copies silently adjudicate against
# the wrong source tree.
etcd_version='3.6.14'
source_commit='fc04cf702b0a46c2fd85547a2be05705b100a496'
source_archive_sha256='c02ebbf6af5f9266f111009fb8d585649a9fcafe5788c200f5a28a7f00d438f0'
go_version='go1.26.8'

etcd_version_arg=''
source_commit_arg=''
source_archive_sha256_arg=''
while (( $# > 0 )) && [[ "$1" == --* ]]; do
  case "$1" in
    --etcd-version|--source-commit|--source-archive-sha256)
      if (( $# < 2 )); then
        printf 'missing value for %s\n' "$1" >&2
        usage
        exit 2
      fi
      case "$1" in
        --etcd-version) etcd_version_arg="$2" ;;
        --source-commit) source_commit_arg="$2" ;;
        --source-archive-sha256) source_archive_sha256_arg="$2" ;;
      esac
      shift 2
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done
if (( $# == 0 )); then
  usage
  exit 2
fi
pin_options=0
if [[ -n "${etcd_version_arg}" ]]; then pin_options=$((pin_options + 1)); fi
if [[ -n "${source_commit_arg}" ]]; then pin_options=$((pin_options + 1)); fi
if [[ -n "${source_archive_sha256_arg}" ]]; then pin_options=$((pin_options + 1)); fi
if (( pin_options != 0 && pin_options != 3 )); then
  printf '%s\n' \
    '--etcd-version, --source-commit, and --source-archive-sha256 must be provided together' >&2
  exit 2
fi
if (( pin_options == 3 )); then
  etcd_version="${etcd_version_arg}"
  source_commit="${source_commit_arg}"
  source_archive_sha256="${source_archive_sha256_arg}"
fi
if [[ ! "${etcd_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || [[ ! "${source_commit}" =~ ^[0-9a-f]{40}$ ]] \
  || [[ ! "${source_archive_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
  printf '%s\n' 'invalid pin: version must be X.Y.Z, commit 40 hex digits, sha256 64 hex digits' >&2
  exit 2
fi

for binary in "$@"; do
  if [[ ! -f "${binary}" || -L "${binary}" || ! -s "${binary}" ]]; then
    echo "release input is not a regular nonempty binary: ${binary}" >&2
    exit 1
  fi
done

# Split a govulncheck v1.6.0 text report into advisory IDs by section.
# Reachable findings are rendered under '=== Symbol Results ===';
# findings in packages that are imported but not called, or modules that are
# only required, are rendered under '=== Package Results ===' and
# '=== Module Results ===' (both only with '-show verbose'). REACH selects
# the reachable set, INFO the unreachable set.
classify_findings() {
  local report="$1" want="$2"
  awk -v want="${want}" '
    /^=== Symbol Results ===$/ { kind = "REACH"; next }
    /^=== Package Results ===$/ { kind = "INFO"; next }
    /^=== Module Results ===$/ { kind = "INFO"; next }
    /^=== / { kind = ""; next }
    kind == want {
      line = $0
      while (match(line, /GO-[0-9]+-[0-9]+/)) {
        print substr(line, RSTART, RLENGTH)
        line = substr(line, RSTART + RLENGTH)
      }
    }
  ' "${report}" | sort -u
}

work="$(mktemp -d)"
# The Go module cache intentionally makes downloaded module directories
# read-only. This private temporary tree must still be removed on failure.
trap 'chmod -R u+w "${work}" 2>/dev/null || true; rm -rf "${work}"' EXIT
scanner_dir="${work}/scanner"
mkdir "${scanner_dir}"
# The scanner runs on the build host even when the binary targets Linux.
GOBIN="${scanner_dir}" GOOS="$(go env GOHOSTOS)" GOARCH="$(go env GOHOSTARCH)" \
  go install golang.org/x/vuln/cmd/govulncheck@v1.6.0

# Stage 1: binary scan, unchanged from the previous single-stage gate.
findings_file="${work}/binary-findings.txt"
: > "${findings_file}"
adjudication_needed=0
for binary in "$@"; do
  printf 'Checking release binary: %s\n' "${binary}"
  report="${work}/binary-report.txt"
  status=0
  "${scanner_dir}/govulncheck" -mode=binary "${binary}" >"${report}" 2>&1 || status=$?
  cat "${report}"
  case "${status}" in
    0)
      ;;
    3)
      adjudication_needed=1
      classify_findings "${report}" REACH >> "${findings_file}"
      ;;
    *)
      printf 'govulncheck binary scan failed for %s with status %d\n' "${binary}" "${status}" >&2
      exit 1
      ;;
  esac
done

if (( adjudication_needed == 0 )); then
  exit 0
fi
binary_ids="$(sort -u "${findings_file}")"
if [[ -z "${binary_ids}" ]]; then
  printf '%s\n' 'binary scan reported findings but its report could not be parsed; failing closed' >&2
  exit 1
fi

# Stage 2: adjudicate the binary findings against the pinned upstream source.
printf 'Binary-mode findings require source-level adjudication against the pinned upstream source.\n'
printf 'Adjudicating with etcd %s, source commit %s\n' "${etcd_version}" "${source_commit}"

# Resolve the release toolchain exactly like build-release-etcdutl.sh, then
# pin it for every nested invocation of the go command that govulncheck
# performs while loading the source.
go_root="$(go env GOROOT)"
go_bin="${go_root}/bin/go"
found_go_version="$("${go_bin}" env GOVERSION)"
if [[ "${found_go_version}" != "${go_version}" ]]; then
  printf 'source adjudication requires the release toolchain %s, found %s; failing closed\n' \
    "${go_version}" "${found_go_version}" >&2
  exit 1
fi

source_url="https://codeload.github.com/etcd-io/etcd/tar.gz/${source_commit}"
archive="${work}/etcd-source.tar.gz"
if ! curl --fail --location --proto '=https' --tlsv1.2 --output "${archive}" "${source_url}"; then
  printf 'unable to download the pinned source %s (no network or upstream gone); failing closed\n' \
    "${source_url}" >&2
  exit 1
fi
if ! printf '%s  %s\n' "${source_archive_sha256}" "${archive}" \
  | sha256sum --check --strict; then
  printf '%s\n' 'pinned source archive checksum mismatch; failing closed' >&2
  exit 1
fi

# The verified source archive binds the complete tree; these checks also
# prevent a version-label or module-path mismatch during a future pin bump.
version_pattern="${etcd_version//./\\.}"
source_root="${work}/source/etcd-${source_commit}"
if ! (
  mkdir "${work}/source"
  tar --extract --gzip --file "${archive}" --directory "${work}/source"
  test -d "${source_root}/etcdutl"
  grep -Eq "^[[:space:]]*Version[[:space:]]*=[[:space:]]*\"${version_pattern}\"$" \
    "${source_root}/api/version/version.go"
  grep -Fxq 'module go.etcd.io/etcd/etcdutl/v3' "${source_root}/etcdutl/go.mod"
); then
  printf '%s\n' 'pinned source archive did not verify against the expected etcd tree; failing closed' >&2
  exit 1
fi

# Same environment discipline as build-release-etcdutl.sh so the scan loads
# exactly the module graph and build configuration of the release binary.
export GOENV=off GOFLAGS='' GOWORK=off GOTOOLCHAIN=local
export GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0
export GOEXPERIMENT='' GOFIPS140=off GOTELEMETRY=off
export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
export GOPRIVATE='' GONOPROXY='' GONOSUMDB=''
export PATH="${go_root}/bin:${PATH}"

source_report="${work}/source-report.txt"
status=0
(
  cd "${source_root}/etcdutl" || exit 1
  GOCACHE="${work}/go-cache" GOMODCACHE="${work}/go-modules" \
    "${scanner_dir}/govulncheck" -mode=source -scan symbol -show verbose .
) > "${source_report}" 2>&1 || status=$?
printf '%s\n' '--- Source-level scan of the pinned etcdutl module ---'
cat "${source_report}"

case "${status}" in
  0|3)
    ;;
  *)
    printf 'source-level scan failed with status %d; failing closed\n' "${status}" >&2
    exit 1
    ;;
esac

reachable_ids="$(classify_findings "${source_report}" REACH)"
unreachable_ids="$(classify_findings "${source_report}" INFO)"
if [[ -z "${reachable_ids}" && "${status}" == 3 ]]; then
  printf '%s\n' 'source scan reported findings but its report could not be parsed; failing closed' >&2
  exit 1
fi
if [[ -n "${reachable_ids}" && "${status}" == 0 ]]; then
  printf '%s\n' 'source scan exit status and report sections disagree; failing closed' >&2
  exit 1
fi

# Reviewed, bounded advisory overrides. Each entry must carry a recorded
# adjudication and a removal condition; entries never silence the binary
# scan itself -- they downgrade a source-verdict to informational when the
# reachability trace is a known analysis artifact.
#
# GO-2026-6348 (grpc mem.* OOM): source mode reports reachability only
# through init-time closure dispatch (crc32 table init -> sync.OnceFunc ->
# grpc client reader). etcdutl is an offline CLI (restore/status on local
# files) and never dials gRPC; govulncheck's documented function-pointer
# conservatism produces this trace. REMOVE THIS ENTRY when the pinned etcd
# release ships grpc >= 1.83.1 (see ANCHOR(etcd-pin)); do not extend this
# list without a recorded adjudication in the PR that adds it.
advisory_overrides="GO-2026-6348"

gate_failed=0
for id in ${binary_ids}; do
  if printf '%s\n' "${advisory_overrides}" | grep -Fxq "${id}"; then
    printf "Advisory %s: overridden by a reviewed adjudication (see advisory_overrides in this script); informational.\n" "${id}"
  elif printf '%s\n' "${reachable_ids}" | grep -Fxq "${id}"; then
    printf 'Advisory %s: present in the scanned binary and source scan confirms reachable code paths in this tool; failing the gate.\n' "${id}"
    gate_failed=1
  elif printf '%s\n' "${unreachable_ids}" | grep -Fxq "${id}"; then
    printf "Advisory %s: unreachable in this tool's code paths; tracked until upstream release\n" "${id}"
  else
    printf 'Advisory %s: not classified by the source-level scan; failing closed\n' "${id}" >&2
    gate_failed=1
  fi
done
for id in ${reachable_ids}; do
  if ! grep -Fxq "${id}" "${findings_file}"; then
    printf 'Advisory %s: source scan confirms reachable code paths in this tool but the binary scan did not flag it; failing the gate.\n' "${id}"
    gate_failed=1
  fi
done
if (( gate_failed )); then
  exit 1
fi

printf 'Gate result: no advisory is reachable from the etcdutl entry points; binary-mode findings are recorded above as informational.\n'
exit 0
