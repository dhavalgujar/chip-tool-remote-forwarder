#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Builds chip-tool-gw (upstream chip-tool's commands plus the client for the
# Matter gateway) and mgw-host (the gateway relay on a host, for
# tests) against a connectedhomeip checkout. chip-tool's own sources stay
# unmodified; CHIP gets one patch (patches/): a session lookup hook in
# CASESessionManager, so chip-tool asks the gateway for a session instead of
# running CASE with the device.
#
# Usage: build.sh CHIP_ROOT [OUT_DIR]
#   CHIP_ROOT  a connectedhomeip checkout with its submodules (tested at
#              7d3dfb6c06b3cc696186f86d527b2f387a5603df)
#   OUT_DIR    default CHIP_ROOT/out/chip-tool-gw
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
CHIP=$(cd "${1:?usage: build.sh CHIP_ROOT [OUT_DIR]}" && pwd)
OUT=${2:-$CHIP/out/chip-tool-gw}
case $OUT in /*) ;; *) OUT=$PWD/$OUT ;; esac # relative to where it was run, not CHIP_ROOT

if ! grep -q SetSessionLookupHook "$CHIP/src/app/CASESessionManager.h"; then
    git -C "$CHIP" apply "$HERE"/patches/0001-*.patch
fi

# The GN root's links: CHIP's build overrides, CHIP itself, the core shared
# with the component.
mkdir -p "$HERE/third_party"
ln -sfn "$CHIP/examples/build_overrides" "$HERE/build_overrides"
ln -sfn "$CHIP" "$HERE/third_party/connectedhomeip"
ln -sfn ../components/esp32_matter_gateway/core "$HERE/core"

cd "$CHIP"
if ! command -v gn > /dev/null; then
    set +u
    . scripts/activate.sh > /dev/null
    set -u
fi
command -v gn > /dev/null || { echo "build.sh: no gn: set up CHIP's environment first (scripts/bootstrap.sh)" >&2; exit 1; }
gn gen --root="$HERE" "$OUT"
ninja -C "$OUT" chip-tool-gw mgw-host
ls -l "$OUT/chip-tool-gw" "$OUT/mgw-host"
