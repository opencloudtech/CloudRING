#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
if [[ "${mode}" != "dco" && "${mode}" != "cla" ]]; then
  echo "usage: validate-contribution-range.sh dco|cla" >&2
  exit 2
fi

case "${GITHUB_EVENT_NAME:-}" in
  pull_request)
    base_sha="$(jq -r '.pull_request.base.sha // empty' "${GITHUB_EVENT_PATH}")"
    head_sha="$(jq -r '.pull_request.head.sha // empty' "${GITHUB_EVENT_PATH}")"
    ;;
  merge_group)
    base_sha="$(jq -r '.merge_group.base_sha // empty' "${GITHUB_EVENT_PATH}")"
    head_sha="$(jq -r '.merge_group.head_sha // empty' "${GITHUB_EVENT_PATH}")"
    ;;
  push)
    base_sha="$(jq -r '.before // empty' "${GITHUB_EVENT_PATH}")"
    head_sha="$(jq -r '.after // empty' "${GITHUB_EVENT_PATH}")"
    ;;
  *)
    echo "unsupported contribution-validation event" >&2
    exit 1
    ;;
esac

head_sha="${head_sha:-${GITHUB_SHA:-}}"
test -n "${head_sha}"
git cat-file -e "${head_sha}^{commit}"
if [[ -n "${base_sha}" && ! "${base_sha}" =~ ^0+$ ]]; then
  git cat-file -e "${base_sha}^{commit}"
  history_spec="${base_sha}..${head_sha}"
else
  history_spec="${head_sha}"
fi

if [[ "${mode}" == "cla" ]]; then
  test -s CLA.md
  grep -Fq "By submitting a contribution" CLA.md
  grep -Fq "right to contribute" CLA.md
  grep -Fq "Apache-2.0" CLA.md
  grep -Fq "matching Signed-off-by trailer records the contributor's assent" CLA.md
fi

identity_pattern='^([^<>]*[^<>[:space:]])[[:space:]]+<([^<>[:space:]]+@[^<>[:space:]]+)>$'
commit_count=0
failed=0
while IFS= read -r commit; do
  # GitHub merge queues create a synthetic two-parent tip. It carries no
  # contributor-authored content; the commits introduced through its second
  # parent remain in the validated range.
  if [[ "${GITHUB_EVENT_NAME}" == "merge_group" && "${commit}" == "${head_sha}" ]]; then
    read -r -a parents <<<"$(git rev-list --parents -n 1 "${commit}")"
    if (( ${#parents[@]} > 2 )); then
      continue
    fi
  fi

  commit_count=$((commit_count + 1))
  author_name="$(git show -s --format='%an' "${commit}")"
  author_email="$(git show -s --format='%ae' "${commit}")"
  author_identity="${author_name} <${author_email}>"
  if [[ ! "${author_identity}" =~ ${identity_pattern} ]]; then
    git show -s --format='Invalid raw author identity: %h' "${commit}" >&2
    failed=1
    continue
  fi
  author_key="${BASH_REMATCH[1]}<${BASH_REMATCH[2],,}>"
  author_email_key="${BASH_REMATCH[2],,}"

  signoffs=()
  signoff_emails=()
  coauthors=()
  malformed=0
  while IFS= read -r trailer; do
    key="${trailer%%:*}"
    value="${trailer#*:}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    case "${key,,}" in
      signed-off-by)
        if [[ ! "${value}" =~ ${identity_pattern} ]]; then
          malformed=1
          continue
        fi
        signoffs+=("${BASH_REMATCH[1]}<${BASH_REMATCH[2],,}>")
        signoff_emails+=("${BASH_REMATCH[2],,}")
        ;;
      co-authored-by)
        if [[ ! "${value}" =~ ${identity_pattern} ]]; then
          malformed=1
          continue
        fi
        coauthors+=("${BASH_REMATCH[1]}<${BASH_REMATCH[2],,}>")
        ;;
    esac
  done < <(git show -s --format=%B "${commit}" | git interpret-trailers --parse)

  author_signed=0
  for signoff in "${signoffs[@]}"; do
    if [[ "${signoff}" == "${author_key}" ]]; then
      author_signed=1
      break
    fi
  done
  # GitHub may rewrite only the display name on a protected squash commit
  # while preserving the contributor email and submitted sign-off. PR commits
  # still require the exact author name and email pair.
  if (( author_signed == 0 )) && [[ "${GITHUB_EVENT_NAME}" == "push" ]]; then
    for signoff_email in "${signoff_emails[@]}"; do
      if [[ "${signoff_email}" == "${author_email_key}" ]]; then
        author_signed=1
        break
      fi
    done
  fi
  if (( malformed != 0 || author_signed == 0 )); then
    git show -s --format='Contributor sign-off mismatch: %h' "${commit}" >&2
    failed=1
  fi
  for coauthor_key in "${coauthors[@]}"; do
    coauthor_signed=0
    for signoff in "${signoffs[@]}"; do
      if [[ "${signoff}" == "${coauthor_key}" ]]; then
        coauthor_signed=1
        break
      fi
    done
    if (( coauthor_signed == 0 )); then
      git show -s --format='Contributor co-author sign-off missing: %h' "${commit}" >&2
      failed=1
    fi
  done
done < <(git rev-list --reverse "${history_spec}")

if (( commit_count == 0 )); then
  echo "no contributor-authored commits found in protected event range" >&2
  exit 1
fi
exit "${failed}"
