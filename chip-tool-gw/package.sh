#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Packs a chip-tool-gw build for a machine without CHIP's environment (a
# sandboxed VM, for example): chip-tool-gw-NAME/ with bin/chip-tool-gw (stripped), lib/
# (the libraries a stock Linux image lacks: libevent's), mgw.sh, and paa/ (the
# production and development PAA roots device attestation trusts), as
# DEST/chip-tool-gw-NAME-linux-x86_64.tgz with its .sha256.
#
# Usage: package.sh CHIP_ROOT OUT_DIR NAME DEST
#   CHIP_ROOT  the connectedhomeip checkout chip-tool-gw was built against
#   OUT_DIR    build.sh's OUT_DIR
#   NAME       the version, e.g. v0.1.0
# PAA_PRODUCTION: a directory of production PAA roots (.der), e.g. fetched from
# the DCL; default: the checkout's copy. paa/SOURCE says which was used.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
CHIP=$(cd "${1:?usage: package.sh CHIP_ROOT OUT_DIR NAME DEST}" && pwd)
OUT=$(cd "${2:?usage: package.sh CHIP_ROOT OUT_DIR NAME DEST}" && pwd)
NAME=${3:?usage: package.sh CHIP_ROOT OUT_DIR NAME DEST}
mkdir -p "${4:?usage: package.sh CHIP_ROOT OUT_DIR NAME DEST}"
DEST=$(cd "$4" && pwd)

base=chip-tool-gw-$NAME
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
dir=$work/$base
mkdir -p "$dir/bin" "$dir/lib" "$dir/paa"
strip -o "$dir/bin/chip-tool-gw" "$OUT/chip-tool-gw"
for lib in libevent_core libevent_pthreads; do
    path=$(ldd "$OUT/chip-tool-gw" | awk -v l="$lib" '$1 ~ "^" l "-" { print $3 }')
    [ -n "$path" ] || { echo "package.sh: chip-tool-gw doesn't link $lib" >&2; exit 1; }
    cp -L "$path" "$dir/lib/"
done
cp "$HERE/mgw.sh" "$dir/"
printf '%s\n' "$NAME" > "$dir/VERSION" # matter.connect's "client" names the release to use
production=${PAA_PRODUCTION:-$CHIP/credentials/production/paa-root-certs}
cp "$production"/*.der "$CHIP"/credentials/development/paa-root-certs/*.der "$dir/paa/"
if [ -n "${PAA_PRODUCTION:-}" ]; then
    echo "production roots: the DCL, $(date -u +%Y-%m-%d); development roots: connectedhomeip $(git -C "$CHIP" rev-parse --short HEAD)"
else
    echo "production and development roots: connectedhomeip $(git -C "$CHIP" rev-parse --short HEAD)"
fi > "$dir/paa/SOURCE"
cat "$dir/paa/SOURCE"

tarball=$base-linux-x86_64.tgz
tar -C "$work" --owner=0 --group=0 --numeric-owner -czf "$DEST/$tarball" "$base"
(cd "$DEST" && sha256sum "$tarball" > "$tarball.sha256")
cat "$DEST/$tarball.sha256"
