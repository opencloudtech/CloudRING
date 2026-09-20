#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || ! "$1" =~ ^[0-9a-f]{40}$ || -e "$2" ]]; then
  echo "usage: checkout-release-source.sh HEAD_SHA NEW_DIRECTORY" >&2
  exit 2
fi
[[ "$(git rev-parse HEAD)" == "$1" ]]
[[ -z "$(git status --porcelain)" ]]
source_root="$(git rev-parse --show-toplevel)"
git init --quiet "$2"
git -C "$2" fetch --quiet --no-tags --depth=1 "${source_root}" "$1"
git -C "$2" -c core.autocrlf=false checkout --quiet --detach "$1"
[[ "$(git -C "$2" rev-parse HEAD)" == "$1" ]]
[[ -z "$(git -C "$2" tag --list)" ]]
[[ -z "$(git -C "$2" status --porcelain)" ]]
