#!/usr/bin/env bash

# Based on https://github.com/BurntSushi/jiff/tree/master/scripts/release.
# You'll need Bash, Cargo 1.90 or later, jq, Git, and a configured Git signing
# key.
#
# The scripts release signa, signa-core and signa-ua, any of them at a time,
# with one release commit and a tag per crate on it.
# Start with a clean working tree and use a separate branch for the bump:
#
#   git switch main
#   git pull --ff-only
#   git switch -c release
#   scripts/release/commit signa=0.4.0 signa-core=0.1.0
#   git push -u origin release
#
# Open a PR and merge it into main. Once it's merged, update local main and
# push the signed release tags:
#
#   git switch main
#   git pull --ff-only
#   scripts/release/publish signa signa-core
#
# commit bumps each crate and the requirement of each crate that depends on
# it, runs the tests and cargo publish --dry-run for all of them, and makes
# the release commit. A crate without `=version` gets its next patch. The dry
# run packages the crates together, so signa verifies against the signa-core
# being released before that is on crates.io.
#
# publish puts a signed tag per crate on the release commit and pushes them,
# and the publish workflow uploads the crates through Trusted Publishing.
# signa's tags are its bare version, such as `0.4.0`, and the others carry
# their name, such as `signa-core-0.1.0`.
#
# A crate's first release goes to crates.io by hand, since Trusted Publishing
# can only be set up for a crate that is already there. After the merge, run
# `cargo publish -p <crate>` with a token, add the publish workflow as its
# trusted publisher, and then run publish. The workflow skips a version that is
# on crates.io already.
#
# You can also use update-version to prepare a version change yourself.
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

# The crates these scripts release, in the order a release commit names them.
# shellcheck disable=SC2034 # commit reads it.
crates=(signa signa-core signa-ua)

validate_crate() {
  case "$1" in
    signa | signa-core | signa-ua) ;;
    *) die "expected signa, signa-core or signa-ua, got: $1" ;;
  esac
}

manifest_of() {
  echo "crates/$1/Cargo.toml"
}

# The tag of a release, the bare version for signa as before the split.
tag_of() {
  if [[ "$1" == signa ]]; then
    echo "$2"
  else
    echo "$1-$2"
  fi
}

current_version() {
  cargo metadata --offline --no-deps --format-version 1 \
    | jq -er --arg crate "$1" '.packages[] | select(.name == $crate) | .version'
}
