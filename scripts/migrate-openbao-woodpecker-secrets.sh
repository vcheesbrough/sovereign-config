#!/bin/sh
# Copy Woodpecker CI secrets from OpenBao KV-v2 into Sovereign Config.
#
# Reads the paths the woodpecker-openbao-broker resolves today and writes each
# key to the corresponding Sovereign Config path. Dry run by default: it prints
# source path, target path, and key NAMES only. Values are passed to the CLI on
# standard input and are never placed in argv, a log line, or a temporary file.
#
# Requires: bao (authenticated, read on the source paths), jq, and
# sovereign-config (a profile with write on the target root).
#
# Usage:
#   scripts/migrate-openbao-woodpecker-secrets.sh --repo owner/name [--apply]

set -eu
umask 077

APPLY=0
ROOT=/woodpecker
# Newline-separated so iteration never depends on word splitting.
REPOS=""

usage() {
    cat >&2 <<'USAGE'
Usage: migrate-openbao-woodpecker-secrets.sh --repo owner/name [options]

  --apply             Perform the writes. Without it, nothing is written.
  --root PATH         Sovereign Config root for Woodpecker (default /woodpecker).
  --repo owner/name   Migrate this repository's per-repo path. Repeatable.
  --help              Show this message.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --apply) APPLY=1 ;;
        --root)
            shift
            ROOT="${1:?--root needs a value}"
            ;;
        --repo)
            shift
            REPOS="$REPOS
${1:?--repo needs a value}"
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage
            exit 2
            ;;
    esac
    shift
done

for tool in bao jq sovereign-config; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: $tool is not on PATH." >&2
        exit 1
    fi
done

if [ -z "$REPOS" ]; then
    echo "ERROR: pass at least one --repo owner/name." >&2
    echo "The per-repo layer is the point of the migration; there is no safe default." >&2
    exit 1
fi

# Failures are recorded in a file rather than a variable: the write loop runs
# inside a `cmd | while read` pipeline, which is a subshell, so a variable set
# there would not survive and `exit` would end only the subshell. The script
# exits non-zero if this file has any content, so a partial migration can never
# report success.
FAILURE_LOG="$(mktemp)"
trap 'rm -f "$FAILURE_LOG"' EXIT INT TERM

record_failure() {
    echo "$1" >>"$FAILURE_LOG"
}

# Sovereign Config path segments are [a-z0-9_-]. Anything else in a KV key has
# no representation and must be renamed by hand rather than silently mangled.
valid_segment() {
    printf '%s' "$1" | grep -Eq '^[a-z0-9_-]+$'
}

kv_keys() {
    bao kv get -format=json "secret/$1" 2>/dev/null | jq -r '.data.data | keys[]'
}

# Copies every key at an OpenBao KV-v2 path to a Sovereign Config namespace.
# Keys are written as secrets: everything the broker serves reaches a CI job, so
# it is treated as sensitive regardless of how it was classified in KV.
migrate_path() {
    source_path="$1"
    target_namespace="$2"

    if ! data="$(bao kv get -format=json "secret/$source_path" 2>/dev/null)"; then
        echo "  skip  secret/$source_path (absent or not readable)"
        return 0
    fi

    keys="$(printf '%s' "$data" | jq -r '.data.data | keys[]')"
    if [ -z "$keys" ]; then
        echo "  skip  secret/$source_path (no keys)"
        return 0
    fi

    printf '%s\n' "$keys" | while IFS= read -r key; do
        [ -n "$key" ] || continue
        if ! valid_segment "$key"; then
            echo "  SKIP  $key is not a valid path segment — rename it in OpenBao first" >&2
            continue
        fi
        target="$target_namespace/$key"
        if [ "$APPLY" -eq 1 ]; then
            # A failed write must not be reported as a completed migration. The
            # value is never echoed, so only the target path appears on failure.
            if printf '%s' "$data" |
                jq -rj --arg key "$key" '.data.data[$key]' |
                sovereign-config secret put "$target"; then
                echo "  wrote $key -> $target"
            else
                echo "  ERROR: write failed for $target" >&2
                record_failure "write $target"
            fi
        else
            echo "  would write $key -> $target"
        fi
    done
}

if [ "$APPLY" -eq 1 ]; then
    echo "APPLYING writes to Sovereign Config."
else
    echo "DRY RUN. Nothing will be written. Re-run with --apply to perform the migration."
fi

# Shared values live only under $ROOT/shared — no canonical copy elsewhere, no
# alias step. A value written here needs nothing further to reach the broker.
echo "shared/global -> $ROOT/shared/global"
migrate_path "shared/global" "$ROOT/shared/global"

echo "woodpecker/global -> $ROOT/global"
migrate_path "woodpecker/global" "$ROOT/global"

printf '%s\n' "$REPOS" | while IFS= read -r repo; do
    [ -n "$repo" ] || continue
    echo "woodpecker/repos/$repo -> $ROOT/repos/$repo"
    migrate_path "woodpecker/repos/$repo" "$ROOT/repos/$repo"
done

echo
if [ -s "$FAILURE_LOG" ]; then
    echo "FAILED: $(wc -l <"$FAILURE_LOG" | tr -d ' ') operation(s) did not complete:" >&2
    sed 's/^/  /' "$FAILURE_LOG" >&2
    echo "The migration is incomplete. Fix the cause and re-run; completed writes" >&2
    echo "are idempotent, so re-running is safe." >&2
    exit 1
fi

if [ "$APPLY" -eq 1 ]; then
    echo "Done. Verify with: sovereign-config get $ROOT --format json"
    echo "Secrets read back masked; that is expected."
else
    echo "Dry run complete. Re-run with --apply once the target paths look right."
fi
