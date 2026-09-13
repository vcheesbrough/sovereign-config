#!/bin/sh
# Unit tests for ci-prune-cargo-target.sh. POSIX sh, no dependencies beyond the
# coreutils the CI images already provide. Run from anywhere:
#   scripts/ci-prune-cargo-target-test.sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
prune="$script_dir/ci-prune-cargo-target.sh"

failures=0

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

pass() {
  echo "ok: $1"
}

# 1 MiB of incompressible-enough filler; two of these exceed a 1 MiB ceiling.
make_filler() {
  dd if=/dev/zero of="$1" bs=1024 count=1024 status=none
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# --- under the ceiling: the cache survives -----------------------------------
target="$work/under"
mkdir -p "$target/debug/deps"
make_filler "$target/debug/deps/libfoo.rlib"

CI_CARGO_TARGET_MAX_MIB=64 "$prune" "$target" >/dev/null

if [ -f "$target/debug/deps/libfoo.rlib" ]; then
  pass "cache under the ceiling is kept"
else
  fail "cache under the ceiling was wiped"
fi

# --- over the ceiling: the cache is emptied, the mount point survives ---------
target="$work/over"
mkdir -p "$target/debug/deps"
make_filler "$target/debug/deps/libfoo.rlib"
make_filler "$target/debug/deps/libbar.rlib"
make_filler "$target/debug/deps/libbaz.rlib"
# Cargo writes dotfiles at the top level (.rustc_info.json); they must go too,
# or the "wiped" cache still pins stale toolchain state.
printf 'stale\n' > "$target/.rustc_info.json"

CI_CARGO_TARGET_MAX_MIB=1 "$prune" "$target" >/dev/null

if [ -d "$target" ]; then
  pass "the target directory itself survives a wipe"
else
  fail "the target directory was removed — it is a volume mount point"
fi

remaining=$(find "$target" -mindepth 1 | wc -l)
if [ "$remaining" -eq 0 ]; then
  pass "cache over the ceiling is emptied, hidden entries included"
else
  fail "cache over the ceiling still holds $remaining entries"
fi

# --- at the ceiling: kept (the comparison is inclusive) ----------------------
# The tightest ceiling that still contains the cache: round its size up to whole
# MiB. Anything smaller would be over.
target="$work/exact"
mkdir -p "$target"
make_filler "$target/filler"
size_kib=$(du -sk "$target" | cut -f1)
size_mib=$(( (size_kib + 1023) / 1024 ))

CI_CARGO_TARGET_MAX_MIB="$size_mib" "$prune" "$target" >/dev/null

if [ -f "$target/filler" ]; then
  pass "cache at the ceiling is kept"
else
  fail "cache at the ceiling was wiped"
fi

CI_CARGO_TARGET_MAX_MIB=$((size_mib - 1)) "$prune" "$target" >/dev/null

if [ -f "$target/filler" ]; then
  fail "cache one MiB over the ceiling was kept"
else
  pass "cache one MiB over the ceiling is wiped"
fi

# --- missing target directory: a no-op, not an error -------------------------
if CI_CARGO_TARGET_MAX_MIB=1 "$prune" "$work/never-created" >/dev/null; then
  pass "a missing target directory is a no-op"
else
  fail "a missing target directory should exit 0 on the first-ever run"
fi

# --- no target directory at all: a usage error -------------------------------
if (unset CARGO_TARGET_DIR; "$prune" >/dev/null 2>&1); then
  fail "no target directory should be a usage error"
else
  pass "no target directory is a usage error"
fi

# --- non-numeric ceiling: a usage error, not a silent wipe -------------------
target="$work/badceiling"
mkdir -p "$target"
make_filler "$target/filler"

if CI_CARGO_TARGET_MAX_MIB=lots "$prune" "$target" >/dev/null 2>&1; then
  fail "a non-numeric ceiling should be a usage error"
elif [ -f "$target/filler" ]; then
  pass "a non-numeric ceiling is rejected without touching the cache"
else
  fail "a non-numeric ceiling wiped the cache"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures test(s) failed" >&2
  exit 1
fi

echo "all ci-prune-cargo-target tests passed"
