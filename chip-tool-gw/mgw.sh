#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# chip-tool-gw, chip-tool whose Matter devices are all reached through the
# Matter gateway, for a machine that reaches the gateway only over TCP: through
# an HTTP CONNECT proxy (MGW_VIA_PROXY=1, the default) or directly
# (MGW_VIA_PROXY=0).
#
#   ./mgw.sh onoff toggle 100 1
#   ./mgw.sh interactive start           (one session for many commands)
#   ./mgw.sh gateway call matter.nodes   (the gateway's own commands)
#   ./mgw.sh gateway call matter.commission --params '{"code":"MT:..."}'
#
# Credentials: connect.json next to this script (MGW_CONNECT_FILE: elsewhere),
# the gateway's connect payload (esp32_matter_gateway_connect(): {"endpoint":
# ..., "secret": ...}), saved with mode 600; chip-tool-gw reads it (MATTER_GW_CONNECT_FILE) and
# never prints the secret. MGW_PROXY_PORT: the proxy port that reaches the
# gateway's network, on $HTTPS_PROXY's host (default 3129).
# Layout: bin/chip-tool-gw, lib/ (its shared libraries), storage/ (the fabric's
# CA once the gateway enrolled; keep it), paa/ (optional: the PAA roots device
# attestation trusts, e.g. connectedhomeip's credentials/production/paa-root-certs
# and, for development devices, credentials/development/paa-root-certs; without
# it chip-tool trusts only the test PAAs).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
conn=${MGW_CONNECT_FILE:-$here/connect.json}
[ -r "$conn" ] || { echo "mgw: save matter.connect's payload as $conn (mode 600)" >&2; exit 2; }
export MATTER_GW_CONNECT_FILE=$conn
if [ "${MGW_VIA_PROXY:-1}" = 1 ]; then
    export MATTER_GW=proxy
    # Never printed; set MATTER_GW_PROXY to override. HTTPS_PROXY with the
    # port switched to the one that reaches the home LAN.
    if [ -z "${MATTER_GW_PROXY:-}" ] && [ -n "${HTTPS_PROXY:-}" ]; then
        p=$HTTPS_PROXY scheme=http
        case $p in *://*) scheme=${p%%://*} p=${p#*://} ;; esac
        p=${p%%/*}                       # no path
        user='' hostport=$p
        case $p in *@*) user=${p%@*}@ hostport=${p##*@} ;; esac
        host=$hostport
        case $hostport in *:*) host=${hostport%:*} ;; esac
        export MATTER_GW_PROXY="$scheme://$user$host:${MGW_PROXY_PORT:-3129}"
        unset p user hostport host scheme
    fi
else
    unset MATTER_GW
fi
export LD_LIBRARY_PATH=$here/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
mkdir -p "$here/storage"
# A command set's help (`./mgw.sh gateway`) takes no options, nor do the
# commands that don't start the stack (payload, dcl, storage).
case "${1:-}" in payload | dcl | storage) exec "$here/bin/chip-tool-gw" "$@" ;; esac
[ $# -ge 2 ] || exec "$here/bin/chip-tool-gw" "$@"
extra=()
case " $* " in *" --storage-directory "*) ;; *) extra+=(--storage-directory "$here/storage") ;; esac
case " $* " in *" --paa-trust-store-path "*) ;; *) [ -d "$here/paa" ] && extra+=(--paa-trust-store-path "$here/paa") ;; esac
exec "$here/bin/chip-tool-gw" "$@" "${extra[@]}"
