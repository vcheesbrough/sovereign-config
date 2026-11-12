#!/bin/sh
# Creates, or updates, the GitHub Release for one deployed version tag, so a
# reader of the tag can find its images:
#
#   scripts/ci-release.sh <tag> <owner/repo> <image>...
#
# A version's tag is written by its first deploy (the Woodpecker deploys'
# `tag` step), so a Release means "this build was deployed". Its notes list
# every image at the tag's version with its digest and package page. A tag
# whose commit main does not contain (a branch deployed to dev) becomes a
# pre-release and never "latest", so the Releases page leads with what main
# ships.
#
# Refuses a name that is not a strict MAJOR.MINOR.PATCH, a tag that does not
# exist, and a version any of whose images is missing: a Release never names
# an image that cannot be pulled. Running it again for a tag rewrites the same
# Release, so it can backfill.
#
# Needs `gh` authenticated with contents write, and a docker that can read the
# images.
set -eu

[ "$#" -ge 3 ] || {
  echo "usage: $0 <tag> <owner/repo> <image>..." >&2
  exit 2
}
tag=$1 repo=$2
shift 2

if ! printf '%s\n' "$tag" | grep -Eqx '(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'; then
  echo "ERROR: '$tag' is not a release version (MAJOR.MINOR.PATCH)" >&2
  exit 1
fi

commit=$(gh api "repos/$repo/commits/refs/tags/$tag" --jq .sha) || {
  echo "ERROR: $repo has no tag $tag" >&2
  exit 1
}
behind=$(gh api "repos/$repo/compare/$commit...main" --jq .behind_by)

notes=$(mktemp)
trap 'rm -f "$notes"' EXIT
# The backticks are Markdown code spans, not command substitutions.
# shellcheck disable=SC2016
{
  printf 'Deployed build `%s` of %s. Its images:\n\n' "$tag" "$commit"
  printf '| Image | Pull |\n| --- | --- |\n'
  for image in "$@"; do
    digest=$(docker buildx imagetools inspect "$image:$tag" --format '{{json .Manifest.Digest}}' | tr -d '"') || {
      echo "ERROR: $image:$tag is not in the registry; a Release names only images that can be pulled" >&2
      exit 1
    }
    case $digest in
      sha256:*) ;;
      *)
        echo "ERROR: $image:$tag has no digest ('$digest')" >&2
        exit 1
        ;;
    esac
    name=${image##*/}
    printf '| [`%s`](https://github.com/%s/pkgs/container/%s) | `docker pull %s:%s@%s` |\n' "$name" "$repo" "$name" "$image" "$tag" "$digest"
  done
  if [ "$behind" != 0 ]; then
    printf '\nA pre-release: main does not contain this commit, which was deployed from a branch.\n'
  fi
} > "$notes"

# A new Release on main takes GitHub's automatic "latest"; an edit must also
# clear a pre-release flag that no longer holds.
if [ "$behind" = 0 ]; then
  create_flags=""
  edit_flags="--prerelease=false"
else
  create_flags="--prerelease --latest=false"
  edit_flags=$create_flags
fi

# The flag variables are lists of flags, split on purpose.
if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
  # shellcheck disable=SC2086
  gh release edit "$tag" --repo "$repo" --title "$tag" --notes-file "$notes" $edit_flags
  echo "updated the Release for $tag"
else
  # shellcheck disable=SC2086
  gh release create "$tag" --repo "$repo" --verify-tag --title "$tag" --notes-file "$notes" $create_flags
  echo "created the Release for $tag"
fi
