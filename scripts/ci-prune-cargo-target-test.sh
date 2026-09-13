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

# 1 MiB of filler; two of these exceed a 1 MiB ceiling.
#
# Random rather than zeroes: a zero-filled file costs almost nothing on a
# filesystem with transparent compression (ZFS with lz4, btrfs with compress=),
# so `du` would report a few KiB and every size assertion below would collapse
# on a developer machine or a CI agent whose Docker storage is on one of those.
#
# Backdated because the script defers a wipe when the cache has been written to
# in the last CI_CARGO_TARGET_IDLE_MIN minutes; freshly created filler would
# look like a concurrent build to every wipe-path test. Tests that want that
# behaviour make a fresh file on purpose.
make_filler() {
  head -c 1048576 /dev/urandom > "$1"
  touch -t 202001010000 "$1"
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Stubs shadow a real command on PATH for one invocation, to force failures no
# permission trick can produce as root.
stub_bin="$work/stub-bin"
mkdir -p "$stub_bin"

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
touch -t 202001010000 "$target/.rustc_info.json"

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

# --- a cache another pipeline is still writing to is not wiped ---------------
# The wipe does not coordinate with cargo's build locks, so emptying the
# directory under a concurrent pipeline would fail that pipeline. A recent write
# is the signal, since the prune runs before this step builds anything.
target="$work/busy"
mkdir -p "$target/debug/deps"
make_filler "$target/debug/deps/libfoo.rlib"
make_filler "$target/debug/deps/libbar.rlib"
make_filler "$target/debug/deps/libbaz.rlib"
printf 'in flight\n' > "$target/debug/deps/libqux.rlib"

# 3 MiB against a 2 MiB ceiling: over it, but under the multiple at which the
# deferral gives way.
CI_CARGO_TARGET_MAX_MIB=2 "$prune" "$target" >/dev/null

if [ -f "$target/debug/deps/libfoo.rlib" ]; then
  pass "a cache written to recently is left alone"
else
  fail "a cache written to recently was wiped under a concurrent build"
fi

# --- but deferring stops once the cache is far over the ceiling --------------
# Deferring forever would give back the unbounded growth this script exists to
# stop, so past the multiple the wipe goes ahead despite the recent write.
CI_CARGO_TARGET_MAX_MIB=1 "$prune" "$target" >/dev/null

if [ -f "$target/debug/deps/libfoo.rlib" ]; then
  fail "a cache far over the ceiling was deferred indefinitely"
else
  pass "a cache far over the ceiling is wiped despite recent writes"
fi

# --- a wipe that cannot finish is not a build failure either -----------------
# Another pipeline creating a file inside a directory rm has just emptied makes
# rm report "Directory not empty"; find passes that on. Stubbing rm is the
# deterministic way to reach it.
target="$work/unwipeable"
mkdir -p "$target"
make_filler "$target/filler"

printf '#!/bin/sh\nexit 1\n' > "$stub_bin/rm"
chmod +x "$stub_bin/rm"

if PATH="$stub_bin:$PATH" CI_CARGO_TARGET_MAX_MIB=0 "$prune" "$target" >/dev/null 2>&1; then
  pass "a wipe that cannot finish still exits 0"
else
  fail "a wipe that cannot finish should not fail the build"
fi

rm -f "$stub_bin/rm"

# --- a non-numeric idle window is a usage error ------------------------------
target="$work/badidle"
mkdir -p "$target"
make_filler "$target/filler"

if CI_CARGO_TARGET_IDLE_MIN=soon CI_CARGO_TARGET_MAX_MIB=0 "$prune" "$target" >/dev/null 2>&1; then
  fail "a non-numeric idle window should be a usage error"
elif [ -f "$target/filler" ]; then
  pass "a non-numeric idle window is rejected without touching the cache"
else
  fail "a non-numeric idle window wiped the cache"
fi

# --- an unmeasurable cache is kept, not a build failure ----------------------
# Stubbing du is the only portable way to force this: CI runs as root, so no
# permission trick makes a real du fail. The branch matters because du exits
# non-zero for any path it cannot stat, including a file a concurrent pipeline
# deleted under its walk.
target="$work/unmeasurable"
mkdir -p "$target"
make_filler "$target/filler"

printf '#!/bin/sh\nexit 1\n' > "$stub_bin/du"
chmod +x "$stub_bin/du"

if PATH="$stub_bin:$PATH" CI_CARGO_TARGET_MAX_MIB=1 "$prune" "$target" >/dev/null 2>&1; then
  if [ -f "$target/filler" ]; then
    pass "a failing du keeps the cache and exits 0"
  else
    fail "a failing du wiped the cache"
  fi
else
  fail "a failing du should not fail the build"
fi

printf '#!/bin/sh\necho "du: cannot read"\n' > "$stub_bin/du"
chmod +x "$stub_bin/du"

if PATH="$stub_bin:$PATH" CI_CARGO_TARGET_MAX_MIB=1 "$prune" "$target" >/dev/null 2>&1; then
  if [ -f "$target/filler" ]; then
    pass "an unparseable du measurement keeps the cache and exits 0"
  else
    fail "an unparseable du measurement wiped the cache"
  fi
else
  fail "an unparseable du measurement should not fail the build"
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
