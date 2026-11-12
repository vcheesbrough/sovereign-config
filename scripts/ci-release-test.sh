#!/bin/sh
# Unit tests for ci-release.sh, with `gh` and `docker` stubbed on PATH. POSIX
# sh, no dependencies. Run from anywhere:
#   scripts/ci-release-test.sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
release="$script_dir/ci-release.sh"

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
mkdir "$work/bin"

# The stubs read their world from files:
#   commit             the tag's commit (absent: the tag does not exist)
#   behind             main's behind_by for that commit
#   release-exists     the Release already exists
#   releases           the tags of the existing full (not pre-) Releases
#   digest-<name>      the image's digest (absent: not in the registry)
# gh appends each release create/edit to `calls`, and copies the notes to `notes`.
cat > "$work/bin/gh" <<'STUB'
#!/bin/sh
world=$STUB_WORLD
case "$1 $2" in
  "api repos/"*/commits/*)
    [ -f "$world/commit" ] || exit 1
    cat "$world/commit"
    ;;
  "api repos/"*/compare/*)
    cat "$world/behind"
    ;;
  "release view")
    [ -f "$world/release-exists" ]
    ;;
  "release list")
    cat "$world/releases" 2>/dev/null || true
    ;;
  "release create" | "release edit")
    echo "$*" >> "$world/calls"
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --notes-file ]; then cp "$2" "$world/notes"; fi
      shift
    done
    ;;
  *)
    echo "unexpected gh $*" >&2
    exit 99
    ;;
esac
STUB
cat > "$work/bin/docker" <<'STUB'
#!/bin/sh
world=$STUB_WORLD
ref=$4
name=${ref##*/}
name=${name%%:*}
[ -f "$world/digest-$name" ] || {
  echo "ERROR: $ref: not found" >&2
  exit 1
}
printf '"%s"\n' "$(cat "$world/digest-$name")"
STUB
chmod +x "$work/bin/gh" "$work/bin/docker"

SERVER=ghcr.io/owner/server
CLI=ghcr.io/owner/cli

world() {
  rm -rf "$work/world"
  mkdir "$work/world"
  echo 0123abc > "$work/world/commit"
  echo 0 > "$work/world/behind"
  echo sha256:aaa > "$work/world/digest-server"
  echo sha256:ccc > "$work/world/digest-cli"
  : > "$work/world/calls"
}

run_release() {
  PATH="$work/bin:$PATH" STUB_WORLD="$work/world" sh "$release" "$@" >/dev/null 2>"$work/stderr"
}

calls() {
  cat "$work/world/calls"
}

contains() {
  case $1 in *"$2"*) return 0 ;; esac
  return 1
}

world
if run_release 2.50.3 owner/repo "$SERVER" "$CLI"; then
  notes=$(cat "$work/world/notes")
  # The backticks are Markdown code spans in the expected notes.
  # shellcheck disable=SC2016
  if contains "$notes" '`docker pull ghcr.io/owner/server:2.50.3@sha256:aaa`' \
    && contains "$notes" '`docker pull ghcr.io/owner/cli:2.50.3@sha256:ccc`' \
    && contains "$notes" '(https://github.com/owner/repo/pkgs/container/server)' \
    && contains "$notes" '0123abc'; then
    pass "the notes give each image's pinned pull and package page"
  else
    fail "the notes give each image's pinned pull and package page: $notes"
  fi
  if contains "$(calls)" "release create 2.50.3 --repo owner/repo --verify-tag" && ! contains "$(calls)" "--prerelease" \
    && contains "$(calls)" "--latest" && ! contains "$(calls)" "--latest=false"; then
    pass "a tag on main gets a full Release on the existing tag, latest"
  else
    fail "a tag on main gets a full Release on the existing tag: $(calls)"
  fi
else
  fail "a tag on main gets a Release"
fi

world
echo 2 > "$work/world/behind"
if run_release 2.50.3 owner/repo "$SERVER" && contains "$(calls)" "--prerelease --latest=false" \
  && contains "$(cat "$work/world/notes")" "A pre-release"; then
  pass "a tag main does not contain is a pre-release, never latest"
else
  fail "a tag main does not contain is a pre-release, never latest: $(calls)"
fi

world
: > "$work/world/release-exists"
if run_release 2.50.3 owner/repo "$SERVER" && contains "$(calls)" "release edit 2.50.3" \
  && contains "$(calls)" "--prerelease=false" && ! contains "$(calls)" "release create"; then
  pass "an existing Release is rewritten, not duplicated"
else
  fail "an existing Release is rewritten, not duplicated: $(calls)"
fi

world
printf '2.50.10\n2.49.3\n' > "$work/world/releases"
if run_release 2.50.9 owner/repo "$SERVER" && contains "$(calls)" "--latest=false"; then
  pass "an older version on main never takes latest from a higher one"
else
  fail "an older version on main never takes latest from a higher one: $(calls)"
fi

world
printf '2.50.9\n2.49.3\n' > "$work/world/releases"
if run_release 2.50.10 owner/repo "$SERVER" && ! contains "$(calls)" "--latest=false" && contains "$(calls)" "--latest"; then
  pass "the highest version on main is latest, compared numerically"
else
  fail "the highest version on main is latest, compared numerically: $(calls)"
fi

world
rm "$work/world/digest-cli"
if ! run_release 2.50.3 owner/repo "$SERVER" "$CLI" && [ -z "$(calls)" ] \
  && contains "$(cat "$work/stderr")" "is not in the registry"; then
  pass "a version with a missing image gets no Release"
else
  fail "a version with a missing image gets no Release: $(calls)"
fi

world
rm "$work/world/commit"
if ! run_release 2.50.3 owner/repo "$SERVER" && [ -z "$(calls)" ]; then
  pass "a tag that does not exist gets no Release"
else
  fail "a tag that does not exist gets no Release: $(calls)"
fi

world
for name in 2.50 v2.50.3 2.50.03 '2.50.3;x' 2.50.3-rc1; do
  if run_release "$name" owner/repo "$SERVER"; then
    fail "'$name' is refused as a version"
  fi
done
if [ -z "$(calls)" ]; then
  pass "only strict MAJOR.MINOR.PATCH names are released"
else
  fail "only strict MAJOR.MINOR.PATCH names are released: $(calls)"
fi

if [ "$failures" -gt 0 ]; then
  echo "$failures failure(s)" >&2
  exit 1
fi
echo "all ci-release tests passed"
