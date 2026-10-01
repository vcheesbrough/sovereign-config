#!/bin/sh
# Prints the release tag for this pipeline: the workspace's major.minor from
# Cargo.toml and the Woodpecker pipeline number as the patch, e.g. 2.41.362.
#
# Pipeline numbers are unique and increasing per repository, so every pipeline
# gets its own version with nothing to allocate, and the build and publish
# workflows of one pipeline derive the same tag independently. A re-run is a
# new pipeline, so it gets a new tag on the same commit; deployments resolve the
# highest tag on the commit.
#
#   CI_PIPELINE_NUMBER=362 scripts/ci-release-tag.sh [path/to/Cargo.toml]
set -eu

manifest=${1:-Cargo.toml}
pipeline=${CI_PIPELINE_NUMBER:-}

case $pipeline in
  '' | *[!0-9]* | 0*)
    echo "ERROR: CI_PIPELINE_NUMBER must be a positive integer, got '$pipeline'" >&2
    exit 1
    ;;
esac

[ -r "$manifest" ] || {
  echo "ERROR: cannot read $manifest" >&2
  exit 1
}

# The first `version = "x.y.z"` inside [workspace.package].
version=$(awk '
  /^\[/ { in_package = ($0 == "[workspace.package]") ; next }
  in_package && /^version[[:space:]]*=/ {
    sub(/^version[[:space:]]*=[[:space:]]*"/, "")
    sub(/".*$/, "")
    print
    exit
  }
' "$manifest")

major_minor=$(printf '%s\n' "$version" | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\)\.[0-9][0-9]*$/\1/p')
[ -n "$major_minor" ] || {
  echo "ERROR: no x.y.z version under [workspace.package] in $manifest (got '$version')" >&2
  exit 1
}

printf '%s.%s\n' "$major_minor" "$pipeline"
