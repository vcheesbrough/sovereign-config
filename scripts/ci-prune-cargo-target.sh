#!/bin/sh
# Bound the shared Woodpecker Rust target cache.
#
# Three CI steps (workspace-validation and both validate-authentik-manager-live*
# steps) share one `sovereign-config-contract-target` volume as CARGO_TARGET_DIR.
# Cargo never garbage-collects artifacts from commits it no longer builds, so
# that volume grew to 92.6 GB over two months with nothing reaping it
# (bored card #326).
#
# This script enforces a hard ceiling: measure the target directory and, once it
# exceeds CI_CARGO_TARGET_MAX_MIB, empty it in place so the next build starts
# cold. A whole-directory wipe is used rather than an mtime sweep because a
# partial sweep can leave `.fingerprint` entries whose artifacts are gone, which
# surfaces as a confusing mid-build failure rather than a clean rebuild.
#
# The directory itself is never removed — it is a volume mount point.
#
# Caveat: a wipe does not coordinate with cargo's own build locks, so a wipe
# racing a concurrent pipeline's build would fail that step. A wipe happens on
# the order of once every two months, so the expected collision rate is
# negligible and the failure is a re-runnable one.
#
# Usage: ci-prune-cargo-target.sh [target-dir]
#        (defaults to $CARGO_TARGET_DIR)
set -eu

# 20 GiB. Measured on pipelines 216/217 (card #326): a cold workspace-validation
# leaves ~3.6 GiB behind and each subsequent pipeline adds ~1.9 GiB of
# hash-suffixed workspace artifacts that cargo never reaps, so the ceiling is
# reached roughly every ten pipelines. A cold workspace-validation took 121 s
# against 101 s warm, so the wipe costs tens of seconds when it fires — the
# cache is worth far less than its old 92.6 GB suggested.
DEFAULT_MAX_MIB=20480

target_dir="${1:-${CARGO_TARGET_DIR:-}}"
max_mib="${CI_CARGO_TARGET_MAX_MIB:-$DEFAULT_MAX_MIB}"

if [ -z "$target_dir" ]; then
  echo "ci-prune-cargo-target: no target directory given and CARGO_TARGET_DIR is unset" >&2
  exit 2
fi

case "$max_mib" in
  '' | *[!0-9]*)
    echo "ci-prune-cargo-target: CI_CARGO_TARGET_MAX_MIB must be a whole number of MiB, got '$max_mib'" >&2
    exit 2
    ;;
esac

if [ ! -d "$target_dir" ]; then
  echo "ci-prune-cargo-target: $target_dir does not exist yet, nothing to prune"
  exit 0
fi

# -sk is the portable spelling: both GNU coreutils (in the rust image) and
# busybox (in the alpine image that runs the tests) support it.
#
# A failed or unparseable measurement must never fail the build. The cache is an
# optimisation, and du exits non-zero for any path it cannot stat — including a
# file another pipeline's cargo deleted underneath the walk, which is normal for
# a shared volume.
used_kib=$(du -sk "$target_dir" 2>/dev/null | tail -1 | cut -f1) || true

case "$used_kib" in
  '' | *[!0-9]*)
    echo "ci-prune-cargo-target: could not measure $target_dir — keeping cache"
    exit 0
    ;;
esac

max_kib=$((max_mib * 1024))

if [ "$used_kib" -le "$max_kib" ]; then
  echo "ci-prune-cargo-target: $target_dir is $((used_kib / 1024)) MiB, ceiling $max_mib MiB — keeping cache"
  exit 0
fi

echo "ci-prune-cargo-target: $target_dir is $((used_kib / 1024)) MiB, over the $max_mib MiB ceiling — wiping"
find "$target_dir" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
echo "ci-prune-cargo-target: $target_dir emptied, next build will be cold"
