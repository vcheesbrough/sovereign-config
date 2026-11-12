#!/bin/sh
# Unit tests for ci-publish-images.sh, with `docker` stubbed on PATH. POSIX sh,
# no dependencies. Run from anywhere:
#   scripts/ci-publish-images-test.sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
publish="$script_dir/ci-publish-images.sh"

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

# The stub reads its world from files:
#   local/<image:tag>        exists when the image is loaded; holds "version revision"
#   published/<image:tag>    exists when the registry has it
#   registry-down            makes every registry lookup fail
# and appends every push to pushes.
cat > "$work/bin/docker" <<'STUB'
#!/bin/sh
world=$STUB_WORLD
key() { printf '%s' "$1" | tr '/:' '__'; }
case "$1 $2" in
  "image inspect")
    if [ "$3" = --format ]; then
      ref=$5 field=$4
      read -r version revision < "$world/local/$(key "$ref")"
      case $field in
        *image.version*) echo "$version" ;;
        *image.revision*) echo "$revision" ;;
      esac
    else
      [ -f "$world/local/$(key "$3")" ]
    fi
    ;;
  "buildx imagetools")
    ref=$4
    if [ -f "$world/registry-down" ]; then
      echo "ERROR: failed to do request: dial tcp: lookup ghcr.io: no such host"
      exit 1
    fi
    if [ -f "$world/published/$(key "$ref")" ]; then
      echo "Name: $ref"
      exit 0
    fi
    echo "ERROR: $ref: not found"
    exit 1
    ;;
  "push "*)
    echo "$2" >> "$world/pushes"
    ;;
  *)
    echo "unexpected docker $*" >&2
    exit 99
    ;;
esac
STUB
chmod +x "$work/bin/docker"

SERVER=ghcr.io/owner/server
CLI=ghcr.io/owner/cli

world() {
  rm -rf "$work/world"
  mkdir -p "$work/world/local" "$work/world/published"
  : > "$work/world/pushes"
}

load() {
  printf '%s %s\n' "$2" "$3" > "$work/world/local/$(printf '%s' "$1" | tr '/:' '__')"
}

published() {
  : > "$work/world/published/$(printf '%s' "$1" | tr '/:' '__')"
}

run_publish() {
  PATH="$work/bin:$PATH" STUB_WORLD="$work/world" sh "$publish" "$@" >/dev/null 2>&1
}

pushes() {
  tr '\n' ' ' < "$work/world/pushes" | sed 's/ $//'
}

world
load "$SERVER:2.50.0" 2.50.0 abc
load "$CLI:2.50.0" 2.50.0 abc
if run_publish 2.50.0 abc "$SERVER" "$CLI" && [ "$(pushes)" = "$SERVER:2.50.0 $CLI:2.50.0" ]; then
  pass "publishes every image under the version"
else
  fail "publishes every image under the version (pushed: $(pushes))"
fi

world
load "$SERVER:2.50.0" 2.50.0 abc
load "$CLI:2.50.0" 2.50.0 other
if ! run_publish 2.50.0 abc "$SERVER" "$CLI" && [ -z "$(pushes)" ]; then
  pass "an image from another commit stops the publish before any push"
else
  fail "an image from another commit stops the publish before any push (pushed: $(pushes))"
fi

world
load "$SERVER:2.50.0" 2.49.9 abc
load "$CLI:2.50.0" 2.50.0 abc
if ! run_publish 2.50.0 abc "$SERVER" "$CLI" && [ -z "$(pushes)" ]; then
  pass "an image labelled with another version stops the publish"
else
  fail "an image labelled with another version stops the publish (pushed: $(pushes))"
fi

world
load "$SERVER:2.50.0" 2.50.0 abc
if ! run_publish 2.50.0 abc "$SERVER" "$CLI" && [ -z "$(pushes)" ]; then
  pass "an image that is not loaded stops the publish"
else
  fail "an image that is not loaded stops the publish (pushed: $(pushes))"
fi

world
load "$SERVER:2.50.0" 2.50.0 abc
load "$CLI:2.50.0" 2.50.0 abc
published "$CLI:2.50.0"
if ! run_publish 2.50.0 abc "$SERVER" "$CLI" && [ -z "$(pushes)" ]; then
  pass "a version already published is never overwritten, and nothing else is pushed"
else
  fail "a version already published is never overwritten (pushed: $(pushes))"
fi

world
load "$SERVER:2.50.0" 2.50.0 abc
: > "$work/world/registry-down"
if ! run_publish 2.50.0 abc "$SERVER" && [ -z "$(pushes)" ]; then
  pass "a registry that cannot answer is not taken as 'not published'"
else
  fail "a registry that cannot answer is not taken as 'not published' (pushed: $(pushes))"
fi

if [ "$failures" -gt 0 ]; then
  echo "$failures failure(s)" >&2
  exit 1
fi
echo "all ci-publish-images tests passed"
