#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
if [[ "${mode}" != "dco" && "${mode}" != "cla" ]]; then
  echo "usage: validate-contribution-range.sh dco|cla" >&2
  exit 2
fi

# Approved automation identities are exempt from sign-off validation. A GitHub
# App bot cannot hold DCO/CLA assent: it signs with a service address that
# never matches its commit author identity. The maintainer who configured the
# automation and approves the merge carries the assent for exempted commits
# (see DCO.md and CLA.md). The exemption matches the exact canonical commit
# identity (name plus noreply email), so it never covers human-authored or
# arbitrary "[bot]"-shaped identities; extend it only through a reviewed
# governance change.
approved_automation_identities=(
  "dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>"
  "github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>"
)

is_approved_automation() {
  local identity candidate
  identity="${1} <${2}>"
  for candidate in "${approved_automation_identities[@]}"; do
    if [[ "${identity,,}" == "${candidate,,}" ]]; then
      return 0
    fi
  done
  return 1
}

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
automation_count=0
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

  # Web-flow merge commits (update-branch / merge queue) are committed by
  # GitHub itself and cannot carry a contributor sign-off; the human approval
  # is recorded on the pull request. Same exemption class as dco/action.
  if [[ "$(git show -s --format='%ce' "${commit}")" == "noreply@github.com" ]]; then
    git show -s --format='GitHub web-flow merge commit, sign-off validation skipped: %h' "${commit}"
    continue
  fi
  if is_approved_automation "${author_name}" "${author_email}"; then
    git show -s --format='Approved automation author, sign-off validation skipped: %h (%an)' "${commit}"
    automation_count=$((automation_count + 1))
    continue
  fi

  signoffs=()
  signoff_emails=()
  coauthors=()
  coauthor_names=()
  coauthor_emails=()
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
        coauthor_names+=("${BASH_REMATCH[1]}")
        coauthor_emails+=("${BASH_REMATCH[2],,}")
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
    git show -s --format='Contributor sign-off mismatch: %h (author %an <%ae>)' "${commit}" >&2
    failed=1
  fi
  for coauthor_index in "${!coauthors[@]}"; do
    # Approved automation co-authors are exempt for the same reason as
    # automation authors: a bot cannot grant the assent a sign-off records.
    if is_approved_automation "${coauthor_names[${coauthor_index}]}" "${coauthor_emails[${coauthor_index}]}"; then
      continue
    fi
    coauthor_key="${coauthors[${coauthor_index}]}"
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
  echo "no commits found in protected event range" >&2
  exit 1
fi
if (( automation_count > 0 )); then
  echo "${automation_count} approved automation commit(s) skipped sign-off validation; maintainer merge approval carries their ${mode^^} coverage"
fi
if (( failed != 0 )); then
  echo "sign-off validation failed: every contributor-authored commit needs a Signed-off-by trailer matching its author identity (see ${mode^^}.md)" >&2
fi
exit "${failed}"
