#!/bin/sh
# Self-extracting installer for a first-party Sovereign Config binary.
#
# This is the header template consumed by scripts/make-installer.sh. The builder
# fills the placeholders below and appends a gzip-compressed tar payload after
# the PAYLOAD marker line. The header extracts that payload from its own file
# ($0), verifies its checksum, and installs the binary. Because extraction reads
# $0, the finished installer must be run from a file (download then run) — it
# cannot be piped into a shell.
set -eu

BINARY_NAME="__BINARY_NAME__"
RELEASE_VERSION="__RELEASE_VERSION__"
EXPECTED_SHA256="__PAYLOAD_SHA256__"
PAYLOAD_MARKER="__SOVEREIGN_CONFIG_PAYLOAD_MARKER__"

fail() {
    echo "install-${BINARY_NAME}: $1" >&2
    exit 1
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        fail "no sha256 tool (sha256sum or shasum) is available"
    fi
}

# Resolve this script's own path; the payload lives at the tail of this file.
script="$0"
case "$script" in
    sh | -sh | bash | -bash | dash | -dash | -)
        fail "run the downloaded file directly (sh <file>); it cannot be piped into a shell" ;;
esac
[ -f "$script" ] || fail "cannot locate the installer file to extract from ($script)"

command -v tar >/dev/null 2>&1 || fail "tar is required but was not found"

os="$(uname -s 2>/dev/null || echo unknown)"
arch="$(uname -m 2>/dev/null || echo unknown)"
case "${os}/${arch}" in
    Linux/x86_64 | Linux/amd64) ;;
    *) fail "this installer targets Linux x86_64; detected ${os}/${arch}" ;;
esac

bindir="${SOVEREIGN_CONFIG_BIN:-${HOME:?HOME must be set to locate an install directory}/.local/bin}"

payload_line="$(awk -v marker="$PAYLOAD_MARKER" '$0 == marker { print NR + 1; exit }' "$script")"
[ -n "${payload_line:-}" ] || fail "payload marker not found; the installer file is corrupt"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

tail -n +"$payload_line" "$script" >"$work/payload.tar.gz"

actual_sha256="$(sha256_of "$work/payload.tar.gz")"
[ "$actual_sha256" = "$EXPECTED_SHA256" ] ||
    fail "payload checksum mismatch (expected ${EXPECTED_SHA256}, got ${actual_sha256})"

tar -xzf "$work/payload.tar.gz" -C "$work"
[ -f "$work/$BINARY_NAME" ] || fail "payload did not contain ${BINARY_NAME}"

mkdir -p "$bindir"
staged="$work/${BINARY_NAME}.staged"
cp "$work/$BINARY_NAME" "$staged"
chmod 0755 "$staged"
# mv within the same directory tree is atomic, so a concurrent user of an
# existing binary never observes a partially written file.
mv -f "$staged" "$bindir/$BINARY_NAME"

echo "install-${BINARY_NAME}: installed ${BINARY_NAME} ${RELEASE_VERSION} to ${bindir}/${BINARY_NAME}" >&2

case ":${PATH}:" in
    *":${bindir}:"*) ;;
    *) echo "install-${BINARY_NAME}: note: ${bindir} is not on your PATH" >&2 ;;
esac

"$bindir/$BINARY_NAME" --version || true
exit 0
