#!/bin/sh
# Build a self-extracting installer for a first-party Sovereign Config binary.
#
# The result is scripts/installer-header.sh (with placeholders filled) followed
# by a marker line and a gzip-compressed tar of the binary. Running the result
# extracts the payload from its own file, verifies its checksum, and installs
# the binary into ~/.local/bin (overridable via SOVEREIGN_CONFIG_BIN).
#
# Usage:
#   make-installer.sh --binary <path> --name <installed-name> \
#       --version <version> --output <installer.sh>
#
# A companion <installer.sh>.sha256 (sha256sum format) is written next to the
# output so the download can be verified before it is run.
set -eu

# Must match PAYLOAD_MARKER in installer-header.sh.
PAYLOAD_MARKER="__SOVEREIGN_CONFIG_PAYLOAD_MARKER__"

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
header="${script_dir}/installer-header.sh"

binary=""
name=""
version=""
output=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary) binary="$2"; shift 2 ;;
        --name) name="$2"; shift 2 ;;
        --version) version="$2"; shift 2 ;;
        --output) output="$2"; shift 2 ;;
        --header) header="$2"; shift 2 ;;
        *) echo "make-installer: unknown argument: $1" >&2; exit 2 ;;
    esac
done

for required in binary name version output; do
    eval "value=\${$required}"
    if [ -z "$value" ]; then
        echo "make-installer: --$required is required" >&2
        exit 2
    fi
done

[ -f "$binary" ] || { echo "make-installer: binary not found: $binary" >&2; exit 1; }
[ -f "$header" ] || { echo "make-installer: header template not found: $header" >&2; exit 1; }

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "make-installer: no sha256 tool (sha256sum or shasum) available" >&2
        exit 1
    fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

# Stage the binary under its installed name so the payload untars to that name.
cp "$binary" "$work/$name"
chmod 0755 "$work/$name"
tar -czf "$work/payload.tar.gz" -C "$work" "$name"

payload_sha256="$(sha256_of "$work/payload.tar.gz")"

# Fill the header placeholders. Values are hex/dotted-digits/a bare name — none
# contain the '|' sed delimiter.
sed \
    -e "s|__BINARY_NAME__|${name}|g" \
    -e "s|__RELEASE_VERSION__|${version}|g" \
    -e "s|__PAYLOAD_SHA256__|${payload_sha256}|g" \
    -e "s|__SOVEREIGN_CONFIG_PAYLOAD_MARKER__|${PAYLOAD_MARKER}|g" \
    "$header" >"$work/installer.sh"

# Append the marker line and the raw payload.
printf '%s\n' "$PAYLOAD_MARKER" >>"$work/installer.sh"
cat "$work/payload.tar.gz" >>"$work/installer.sh"

chmod 0755 "$work/installer.sh"

mkdir -p "$(dirname -- "$output")"
cp "$work/installer.sh" "$output"

output_sha256="$(sha256_of "$output")"
printf '%s  %s\n' "$output_sha256" "$(basename -- "$output")" >"${output}.sha256"

echo "make-installer: wrote $output ($(wc -c <"$output") bytes)" >&2
echo "make-installer: wrote ${output}.sha256" >&2
