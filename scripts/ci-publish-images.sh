#!/bin/sh
# Publishes one build's images under its version, once, and only whole:
#
#   scripts/ci-publish-images.sh <version> <commit> <image>...
#
# Each <image> is a name without a tag (ghcr.io/owner/name), already loaded
# locally as <image>:<version>. Before anything is pushed, every image must
# carry this build's labels (org.opencontainers.image.version = <version>,
# org.opencontainers.image.revision = <commit>) and none may be published yet.
# A refusal therefore pushes nothing. A version is published once and never
# overwritten.
#
# These are the checks the Woodpecker deploys' `resolve` step relies on: it
# ships a build only when all its images are published with matching labels
# (woodpecker-plugin-release-versions, release-flow skill).
#
# Needs a docker logged in to the registry with push access.
set -eu

[ "$#" -ge 3 ] || {
  echo "usage: $0 <version> <commit> <image>..." >&2
  exit 2
}
version=$1 commit=$2
shift 2

label() {
  docker image inspect --format "{{ index .Config.Labels \"$2\" }}" "$1"
}

for image in "$@"; do
  ref=$image:$version
  if ! docker image inspect "$ref" >/dev/null 2>&1; then
    echo "ERROR: $ref is not loaded locally" >&2
    exit 1
  fi
  got_version=$(label "$ref" org.opencontainers.image.version)
  got_revision=$(label "$ref" org.opencontainers.image.revision)
  if [ "$got_version" != "$version" ] || [ "$got_revision" != "$commit" ]; then
    echo "ERROR: $ref is labelled version '$got_version' revision '$got_revision'; want '$version' '$commit'" >&2
    exit 1
  fi
done

for image in "$@"; do
  ref=$image:$version
  if output=$(docker buildx imagetools inspect "$ref" 2>&1); then
    echo "ERROR: $ref is already published; a version is published once and never overwritten" >&2
    exit 1
  fi
  case $output in
    *": not found"*) ;;
    *)
      # Unreachable or refusing is not "absent": never publish on a guess.
      echo "ERROR: the registry cannot answer for $ref: $output" >&2
      exit 1
      ;;
  esac
done

for image in "$@"; do
  docker push "$image:$version"
  echo "published $image:$version"
done
