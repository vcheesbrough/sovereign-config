#!/bin/sh
# Claims this build's version and prints it: the workspace's major.minor from
# Cargo.toml plus the next patch on that line, recorded on the remote as
# refs/builds/<version>.
#
# That ref is the record the Woodpecker deploys read: their `resolve` step
# (woodpecker-plugin-release-versions) ships a commit's newest build whose
# images are published, and its `tag` step writes the git tag once deployed.
# So the claim keeps the plugin's contract exactly (release-flow skill):
#
#   - refs/builds/<version> points at an annotated tag object that peels to
#     the commit (resolve matches builds to commits through the peeled line);
#   - it is created by a create-only, atomic push, so two builds can never hold
#     one version. Pointing at a fresh tag object rather than at the commit is
#     what makes create-only hold for two builds of one commit: git skips the
#     lease check when a push leaves a ref at the value it already has;
#   - the patch is one more than the highest release tag or build on the line,
#     or 0, and a build that loses the race re-reads and claims the next one.
#
# A failed build uses its number up, so gaps in the patch sequence mark failed
# builds.
#
#   scripts/ci-claim-build.sh <Cargo.toml> <remote> <commit> <branch> <run-id>
#
# Run inside a checkout holding <commit> (git mktag checks the object exists),
# with push access to <remote>.
set -eu

MAX_ATTEMPTS=20

# The first `version = "x.y.z"` inside [workspace.package], as x.y.
major_minor() {
  version=$(awk '
    /^\[/ { in_package = ($0 == "[workspace.package]"); next }
    in_package && /^version[[:space:]]*=/ {
      sub(/^version[[:space:]]*=[[:space:]]*"/, "")
      sub(/".*$/, "")
      print
      exit
    }
  ' "$1")
  printf '%s\n' "$version" | awk -F. '
    NF == 3 && $1 ~ /^(0|[1-9][0-9]*)$/ && $2 ~ /^(0|[1-9][0-9]*)$/ && $3 ~ /^(0|[1-9][0-9]*)$/ { print $1 "." $2 }
  '
}

# The remote's release tags and builds, one ref name per line, without the
# peeled `^{}` lines.
list_refs() {
  git ls-remote "$1" 'refs/tags/*' 'refs/builds/*' | awk '{ print $2 }' | sed '/\^{}$/d'
}

# Reads ref names on stdin; prints one more than the highest patch of any
# release tag or build on line <major.minor>, or 0. Only strict versions count
# (no leading zeros, no pre-release), as the plugin's semver parse requires.
next_patch() {
  awk -v line="$1." '
    {
      name = $0
      if (!sub(/^refs\/(tags|builds)\//, "", name)) next
      if (index(name, line) != 1) next
      patch = substr(name, length(line) + 1)
      if (patch !~ /^(0|[1-9][0-9]*)$/) next
      if (patch + 1 > next_patch) next_patch = patch + 1
    }
    END { print next_patch + 0 }
  '
}

# claim <remote> <version> <commit> <branch> <run-id>: one create-only push of
# a tag object naming the commit, branch and run. The message keeps the
# plugin's `commit:`/`branch:`/`pipeline:` lines.
claim() {
  object=$(printf 'object %s\ntype commit\ntag %s\ntagger sovereign-config-build <build@github-actions> %s +0000\n\nBuild %s\n\ncommit: %s\nbranch: %s\npipeline: %s\n' \
    "$3" "$2" "$(date +%s)" "$2" "$3" "$4" "$5" | git mktag)
  git push --atomic --porcelain "--force-with-lease=refs/builds/$2:" "$1" "$object:refs/builds/$2" >&2
}

main() {
  [ "$#" -eq 5 ] || {
    echo "usage: $0 <Cargo.toml> <remote> <commit> <branch> <run-id>" >&2
    exit 2
  }
  manifest=$1 remote=$2 commit=$3 branch=$4 run=$5
  [ -r "$manifest" ] || {
    echo "ERROR: cannot read $manifest" >&2
    exit 1
  }
  line=$(major_minor "$manifest")
  [ -n "$line" ] || {
    echo "ERROR: $manifest has no strict MAJOR.MINOR.PATCH version in [workspace.package]" >&2
    exit 1
  }

  attempt=1
  while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
    patch=$(list_refs "$remote" | next_patch "$line")
    version=$line.$patch
    if claim "$remote" "$version" "$commit" "$branch" "$run"; then
      echo "claimed $version for $commit" >&2
      printf '%s\n' "$version"
      return 0
    fi
    # Lost the race only if another build now holds the ref; any other push
    # failure is real and must not be retried into a different version.
    if ! list_refs "$remote" | grep -qx "refs/builds/$version"; then
      echo "ERROR: could not claim $version, and no other build holds it" >&2
      exit 1
    fi
    echo "$version was claimed by another build; retrying (attempt $attempt)" >&2
    attempt=$((attempt + 1))
  done
  echo "ERROR: could not claim a version after $MAX_ATTEMPTS attempts" >&2
  exit 1
}

# The tests source this file for its functions.
if [ "${CI_CLAIM_BUILD_LIB:-}" != 1 ]; then
  main "$@"
fi
