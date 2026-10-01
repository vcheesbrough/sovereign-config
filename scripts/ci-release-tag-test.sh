#!/bin/sh
# Unit tests for ci-release-tag.sh. POSIX sh, no dependencies beyond the
# coreutils the CI images already provide. Run from anywhere:
#   scripts/ci-release-tag-test.sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
release_tag="$script_dir/ci-release-tag.sh"

failures=0

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

pass() {
  echo "ok: $1"
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A manifest shaped like the workspace's: a crate-level version before the
# workspace one, and a dependency table carrying its own version after it.
cat > "$work/Cargo.toml" <<'EOF'
[package]
version = "9.9.9"

[workspace]
members = ["crates/a"]

[workspace.package]
version = "2.41.0"
edition = "2024"

[workspace.dependencies]
serde = { version = "1.0.200" }
EOF

expect_tag() {
  name=$1 pipeline=$2 expected=$3
  if actual=$(CI_PIPELINE_NUMBER=$pipeline sh "$release_tag" "$work/Cargo.toml" 2>/dev/null) &&
    [ "$actual" = "$expected" ]; then
    pass "$name"
  else
    fail "$name: expected '$expected', got '${actual:-<error>}'"
  fi
}

expect_refusal() {
  name=$1 pipeline=$2 manifest=$3
  if CI_PIPELINE_NUMBER=$pipeline sh "$release_tag" "$manifest" >/dev/null 2>&1; then
    fail "$name: expected a refusal"
  else
    pass "$name"
  fi
}

expect_tag "the pipeline number is the patch" 362 "2.41.362"
expect_tag "only [workspace.package] supplies major.minor" 1 "2.41.1"
expect_tag "a large pipeline number is kept whole" 100000 "2.41.100000"

expect_refusal "an unset pipeline number is refused" "" "$work/Cargo.toml"
expect_refusal "a non-numeric pipeline number is refused" "36a" "$work/Cargo.toml"
expect_refusal "pipeline number zero is refused" 0 "$work/Cargo.toml"
expect_refusal "a zero-padded pipeline number is refused" 0362 "$work/Cargo.toml"
expect_refusal "a missing manifest is refused" 362 "$work/absent.toml"

printf '[workspace]\nmembers = []\n' > "$work/no-package.toml"
expect_refusal "a manifest without [workspace.package] is refused" 362 "$work/no-package.toml"

printf '[workspace.package]\nversion = "2.41"\n' > "$work/short.toml"
expect_refusal "a version that is not x.y.z is refused" 362 "$work/short.toml"

if [ "$failures" -ne 0 ]; then
  echo "$failures test(s) failed" >&2
  exit 1
fi
echo "all ci-release-tag tests passed"
