#!/bin/sh
# Unit tests for ci-prune-buildkit-cache.sh. POSIX sh; `docker` is replaced by a
# stub on PATH, so no Docker daemon is needed. Run from anywhere:
#   scripts/ci-prune-buildkit-cache-test.sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
prune="$script_dir/ci-prune-buildkit-cache.sh"

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

stub_bin="$work/stub-bin"
mkdir -p "$stub_bin"
calls="$work/calls"

# The stub prints $STUB_DU for `buildx du` (exiting $STUB_DU_EXIT), exits
# $STUB_PRUNE_EXIT for `buildx prune`, and records every invocation.
cat > "$stub_bin/docker" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >> "$CALLS"
case "$1 $2" in
  "buildx du")
    printf '%s' "$STUB_DU"
    exit "${STUB_DU_EXIT:-0}"
    ;;
  "buildx prune")
    exit "${STUB_PRUNE_EXIT:-0}"
    ;;
esac
exit 97
STUB
chmod +x "$stub_bin/docker"

record() {
  printf 'ID:\t\t%s\nSize:\t\t%s\nDescription:\tcached mount /src/target with id "/sovereign-config-cargo-target"\nType:\t\texec.cachemount\n\n' "$1" "$2"
}

run() {
  : > "$calls"
  output=$(PATH="$stub_bin:$PATH" CALLS="$calls" "$prune" 2>&1) && status=0 || status=$?
}

pruned() {
  grep -qF 'buildx prune --force --filter description~=sovereign-config-cargo-target[^0-9A-Za-z._-]' "$calls"
}

# --- under the ceiling: nothing is pruned -------------------------------------
STUB_DU=$(record a 512MB)
export STUB_DU
CI_BUILDKIT_CACHE_MAX_MIB=1024 run
if [ "$status" -eq 0 ] && ! pruned; then
  pass "cache under the ceiling is kept"
else
  fail "cache under the ceiling was pruned (status $status): $output"
fi

# --- measurement is scoped to this repository's cache mount -------------------
if grep -qF 'buildx du --verbose --filter description~=sovereign-config-cargo-target[^0-9A-Za-z._-]' "$calls"; then
  pass "only the sovereign-config-cargo-target mount is measured"
else
  fail "du was not filtered to the cache mount: $(cat "$calls")"
fi

# --- several records are summed across units, over the ceiling: pruned --------
STUB_DU="$(record a 1.5GB)
$(record b 700MB)
$(record c 512kB)"
export STUB_DU
# 1.5 GB + 700 MB + 512 kB = 2 200 512 000 B = 2098 MiB.
CI_BUILDKIT_CACHE_MAX_MIB=2000 run
if [ "$status" -eq 0 ] && pruned; then
  pass "records are summed and a cache over the ceiling is pruned"
else
  fail "summed cache over the ceiling was not pruned (status $status): $output"
fi
case "$output" in
  *"is 2098 MiB"*) pass "decimal units convert to MiB" ;;
  *) fail "expected 2098 MiB in: $output" ;;
esac

CI_BUILDKIT_CACHE_MAX_MIB=2098 run
if ! pruned; then
  pass "a cache exactly at the ceiling is kept"
else
  fail "a cache exactly at the ceiling was pruned"
fi

# --- no matching record: nothing to prune ------------------------------------
STUB_DU=""
export STUB_DU
CI_BUILDKIT_CACHE_MAX_MIB=1 run
if [ "$status" -eq 0 ] && ! pruned; then
  pass "a missing cache mount is not pruned"
else
  fail "a missing cache mount caused a prune (status $status)"
fi

# --- a failed or unparseable measurement never fails the build ---------------
STUB_DU=$(record a 9GB)
STUB_DU_EXIT=1
export STUB_DU STUB_DU_EXIT
CI_BUILDKIT_CACHE_MAX_MIB=1 run
if [ "$status" -eq 0 ] && ! pruned; then
  pass "a failed measurement keeps the cache and exits 0"
else
  fail "a failed measurement pruned or failed (status $status)"
fi
unset STUB_DU_EXIT

STUB_DU=$(record a 9ZB)
export STUB_DU
CI_BUILDKIT_CACHE_MAX_MIB=1 run
if [ "$status" -eq 0 ] && ! pruned; then
  pass "an unknown size unit keeps the cache and exits 0"
else
  fail "an unknown size unit pruned or failed (status $status)"
fi

# --- a failed prune never fails the build -------------------------------------
STUB_DU=$(record a 9GB)
STUB_PRUNE_EXIT=1
export STUB_DU STUB_PRUNE_EXIT
CI_BUILDKIT_CACHE_MAX_MIB=1 run
if [ "$status" -eq 0 ] && pruned; then
  pass "a failed prune exits 0"
else
  fail "a failed prune failed the step (status $status)"
fi
unset STUB_PRUNE_EXIT

# --- invalid configuration is rejected before touching Docker -----------------
CI_BUILDKIT_CACHE_MAX_MIB=20GB run
if [ "$status" -eq 2 ] && [ ! -s "$calls" ]; then
  pass "a non-numeric ceiling is rejected"
else
  fail "a non-numeric ceiling was accepted (status $status)"
fi

CI_BUILDKIT_CACHE_ID='x" || true' CI_BUILDKIT_CACHE_MAX_MIB=1 run
if [ "$status" -eq 2 ] && [ ! -s "$calls" ]; then
  pass "a cache id that is not a plain id is rejected"
else
  fail "an unsafe cache id was accepted (status $status)"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures test(s) failed" >&2
  exit 1
fi
echo "all ci-prune-buildkit-cache tests passed"
