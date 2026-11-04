#!/usr/bin/env bash

# Based on https://github.com/BurntSushi/jiff/tree/master/scripts/release.
# You'll need Bash, Cargo, jq, Git, and a configured Git signing key.
#
# Start with a clean working tree and use a separate branch for the version
# bump:
#
#   git switch main
#   git pull --ff-only
#   git switch -c release/0.2.1
#   scripts/release/commit 0.2.1
#   git push -u origin release/0.2.1
#
# Open a PR and merge it into main. Once it's merged, update local main and
# push the signed release tag:
#
#   git switch main
#   git pull --ff-only
#   scripts/release/publish
#
# commit runs the tests and cargo publish --dry-run before making the release
# commit. publish creates a signed version tag and pushes it to origin, where
# the publish workflow handles crates.io authentication and upload.
# You can also use update-version to prepare the version change yourself.
# If a check fails after the version bump, fix it and finish the commit by
# hand. The changes stay in your working tree.

# Find the repository from this script so the commands work from any directory.
set -euo pipefail

release_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$release_dir/../.."

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

require_clean() {
  [[ -z "$(git status --porcelain)" ]] || die 'repository must be clean'
}

validate_version() {
  # These scripts only support stable versions for now.
  [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
    || die "expected a stable version such as 0.2.1, got: $1"
}

current_version() {
  cargo metadata --offline --no-deps --format-version 1 \
    | jq -er '.packages[] | select(.name == "signa") | .version'
}
