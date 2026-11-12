#!/bin/sh
# Unit tests for ci-claim-build.sh, against throwaway local bare repositories.
# POSIX sh; needs git. Run from anywhere:
#   scripts/ci-claim-build-test.sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
claim_script="$script_dir/ci-claim-build.sh"

failures=0

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

pass() {
  echo "ok: $1"
}

expect() {
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1: want '$3', got '$2'"; fi
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid

manifest() {
  printf '[workspace]\nmembers = []\n\n[package]\nversion = "9.9.9"\n\n[workspace.package]\nedition = "2021"\nversion = "%s"\n' "$1" > "$work/Cargo.toml"
}

# A fresh checkout with one commit, and an empty bare remote.
fresh() {
  rm -rf "$work/repo" "$work/remote.git"
  git init -q --bare "$work/remote.git"
  git init -q "$work/repo"
  git -C "$work/repo" commit -q --allow-empty -m one
  git -C "$work/repo" rev-parse HEAD
}

run_claim() {
  (cd "$work/repo" && sh "$claim_script" "$work/Cargo.toml" "$work/remote.git" "$1" main gha-1-1)
}

# --- major.minor -------------------------------------------------------------

# shellcheck source=/dev/null
CI_CLAIM_BUILD_LIB=1 . "$claim_script"

manifest 2.50.0
expect "reads major.minor from [workspace.package], not [package]" "$(major_minor "$work/Cargo.toml")" "2.50"
manifest 2.05.0
expect "refuses a non-strict version" "$(major_minor "$work/Cargo.toml")" ""
manifest 2.50
expect "refuses a version without a patch" "$(major_minor "$work/Cargo.toml")" ""

# --- next patch --------------------------------------------------------------

expect "an empty line starts at 0" "$(printf '' | next_patch 2.50)" "0"
expect "counts both tags and builds on the line" "$(printf 'refs/tags/2.50.3\nrefs/builds/2.50.7\nrefs/builds/2.50.5\n' | next_patch 2.50)" "8"
expect "ignores other lines and non-release names" "$(printf 'refs/tags/2.49.99\nrefs/builds/12.50.4\nrefs/tags/2.500.1\nrefs/tags/2.50.03\nrefs/tags/v2.50.4\nrefs/tags/2.50.4-rc1\n' | next_patch 2.50)" "0"

# --- claim, end to end -------------------------------------------------------

manifest 2.50.0
commit=$(fresh)

first=$(run_claim "$commit" 2>/dev/null)
expect "the first claim on a line is .0" "$first" "2.50.0"
expect "the build ref points at an annotated tag object" "$(git -C "$work/remote.git" cat-file -t refs/builds/2.50.0)" "tag"
expect "the build ref peels to the commit" "$(git -C "$work/remote.git" rev-parse 'refs/builds/2.50.0^{commit}')" "$commit"
peeled=$(git ls-remote "$work/remote.git" 'refs/builds/*' | awk '$2 == "refs/builds/2.50.0^{}" { print $1 }')
expect "the remote lists a peeled line for the build" "$peeled" "$commit"
message=$(git -C "$work/remote.git" cat-file -p refs/builds/2.50.0)
case $message in
  *"commit: $commit"*"branch: main"*"pipeline: gha-1-1"*) pass "the tag object names the commit, branch and run" ;;
  *) fail "the tag object names the commit, branch and run: $message" ;;
esac

second=$(run_claim "$commit" 2>/dev/null)
expect "a second build of the same commit claims the next number" "$second" "2.50.1"

git -C "$work/repo" tag 2.50.7 "$commit"
git -C "$work/repo" push -q "$work/remote.git" refs/tags/2.50.7
expect "a release tag on the line moves the counter past it" "$(run_claim "$commit" 2>/dev/null)" "2.50.8"

# --- losing a race -----------------------------------------------------------

commit=$(fresh)
git -C "$work/repo" tag -a -m taken taken "$commit"
git -C "$work/repo" push -q "$work/remote.git" "refs/tags/taken:refs/builds/2.50.0"
listings="$work/listings"
: > "$listings"
# The first listing is stale (taken before the other build pushed); later ones
# are the remote's.
raced=$(
  cd "$work/repo"
  # shellcheck source=/dev/null
  CI_CLAIM_BUILD_LIB=1 . "$claim_script"
  # Called by main, which shellcheck cannot see through the sourced file.
  # shellcheck disable=SC2317
  list_refs() {
    if [ ! -s "$listings" ]; then
      echo stale >> "$listings"
      return 0
    fi
    git ls-remote "$1" 'refs/tags/*' 'refs/builds/*' | awk '{ print $2 }' | sed '/\^{}$/d'
  }
  main "$work/Cargo.toml" "$work/remote.git" "$commit" main gha-2-1 2>/dev/null
)
expect "a build that loses the race claims the next number" "$raced" "2.50.1"
expect "the winner's ref is left alone" "$(git -C "$work/remote.git" cat-file -p refs/builds/2.50.0 | sed -n 's/^tag //p')" "taken"

# --- a push that fails for another reason -----------------------------------

commit=$(fresh)
if (cd "$work/repo" && sh "$claim_script" "$work/Cargo.toml" "$work/missing.git" "$commit" main gha-3-1) >/dev/null 2>&1; then
  fail "an unreachable remote fails the claim"
else
  pass "an unreachable remote fails the claim"
fi

if [ "$failures" -gt 0 ]; then
  echo "$failures failure(s)" >&2
  exit 1
fi
echo "all ci-claim-build tests passed"
