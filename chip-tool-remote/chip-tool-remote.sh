#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# chip-tool-remote, chip-tool whose Matter devices are all reached through the
# forwarder, for a machine that reaches the forwarder only over TCP: through
# an HTTP CONNECT proxy (CHIP_TOOL_REMOTE_VIA_PROXY=1, the default) or directly
# (CHIP_TOOL_REMOTE_VIA_PROXY=0).
#
#   ./chip-tool-remote.sh onoff toggle 100 1
#   ./chip-tool-remote.sh interactive start           (one session for many commands)
#   ./chip-tool-remote.sh forwarder call matter.nodes   (the forwarder's own commands)
#   ./chip-tool-remote.sh forwarder call matter.commission --params '{"code":"MT:..."}'
#
# Credentials: connect.json next to this script (CHIP_TOOL_REMOTE_CONNECT_FILE:
# elsewhere), the forwarder's connect payload (chip_tool_forwarder_connect():
# {"endpoint": ..., "secret": ...}), saved with mode 600; chip-tool-remote
# reads it and never prints the secret. CHIP_TOOL_REMOTE_PROXY_PORT: the proxy
# port that reaches the forwarder's network, on $HTTPS_PROXY's host (default
# 3129).
# Layout: bin/chip-tool-remote, lib/ (its shared libraries), storage/ (the fabric's
# CA once the forwarder enrolled; keep it), paa/ (optional: the PAA roots device
# attestation trusts, e.g. connectedhomeip's credentials/production/paa-root-certs
# and, for development devices, credentials/development/paa-root-certs; without
# it chip-tool trusts only the test PAAs).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
conn=${CHIP_TOOL_REMOTE_CONNECT_FILE:-$here/connect.json}
[ -r "$conn" ] || { echo "chip-tool-remote.sh: save matter.connect's payload as $conn (mode 600)" >&2; exit 2; }
export CHIP_TOOL_REMOTE_CONNECT_FILE=$conn
if [ "${CHIP_TOOL_REMOTE_VIA_PROXY:-1}" = 1 ]; then
    export CHIP_TOOL_REMOTE_TARGET=proxy
    # Never printed; set CHIP_TOOL_REMOTE_PROXY to override. HTTPS_PROXY with the
    # port switched to the one that reaches the home LAN.
    if [ -z "${CHIP_TOOL_REMOTE_PROXY:-}" ] && [ -n "${HTTPS_PROXY:-}" ]; then
        p=$HTTPS_PROXY scheme=http
        case $p in *://*) scheme=${p%%://*} p=${p#*://} ;; esac
        p=${p%%/*}                       # no path
        user='' hostport=$p
        case $p in *@*) user=${p%@*}@ hostport=${p##*@} ;; esac
        host=$hostport
        case $hostport in *:*) host=${hostport%:*} ;; esac
        export CHIP_TOOL_REMOTE_PROXY="$scheme://$user$host:${CHIP_TOOL_REMOTE_PROXY_PORT:-3129}"
        unset p user hostport host scheme
    fi
else
    unset CHIP_TOOL_REMOTE_TARGET
fi
export LD_LIBRARY_PATH=$here/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
mkdir -p "$here/storage"
# A command set's help (`./chip-tool-remote.sh forwarder`) takes no options, nor do the
# commands that don't start the stack (payload, dcl, storage).
case "${1:-}" in payload | dcl | storage) exec "$here/bin/chip-tool-remote" "$@" ;; esac
[ $# -ge 2 ] || exec "$here/bin/chip-tool-remote" "$@"
extra=()
case " $* " in *" --storage-directory "*) ;; *) extra+=(--storage-directory "$here/storage") ;; esac
case " $* " in *" --paa-trust-store-path "*) ;; *) [ -d "$here/paa" ] && extra+=(--paa-trust-store-path "$here/paa") ;; esac
exec "$here/bin/chip-tool-remote" "$@" "${extra[@]}"
