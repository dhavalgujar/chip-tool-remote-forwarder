// SPDX-License-Identifier: Apache-2.0

// A forwarder for chip-tool-remote: chip-tool, wherever it runs, reaches the
// home's Matter devices through this device. chip_tool_forwarder_connect()
// gives the address and secret of a TLS stream (TCP 7401); chip-tool-remote sends
// Matter messages over it, and the device relays them onto its own CASE
// sessions with the devices, over Wi-Fi or Thread. The fabric's CA is
// chip-tool-remote's: the device enrolls once and asks chip-tool-remote to verify and
// sign every device it commissions.
//
// The application calls chip_tool_forwarder_init() at boot and offers
// chip_tool_forwarder_connect() to the controller's user on a channel it
// trusts (for example, a command only the paired owner can call), never on the
// stream itself.
#pragma once

#include <stdbool.h>

#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // The application's own setup is done (for example, paired with its owner), and
    // Bluetooth is CHIP's from this boot on. Until then Matter doesn't start,
    // and whatever a previous owner left in the "matter" partition is erased.
    bool setup_complete;
    // Where chip-tool-remote connects from. NULL: every interface (the local
    // network). Otherwise the two-letter name of an lwIP netif (a tunnel, for
    // example "tn"): the listener is bound to that interface and to the Wi-Fi
    // station's address, opened once both exist and moved when the address
    // changes, and the port isn't open on the local network.
    const char *listen_netif;
} chip_tool_forwarder_config_t;

// At boot.
void chip_tool_forwarder_init(const chip_tool_forwarder_config_t *config);

// The application's setup finished in this boot: the device restarts a few
// seconds later, so that Matter starts.
void chip_tool_forwarder_setup_done(void);

// The stream's endpoint and secret, and the chip-tool-remote release to use
// (client), as {ok, payload} or {ok, error} JSON.
// params: {"rotate": true} replaces the secret first, closing every
// connection. The application's trusted channel only (see above).
cJSON *chip_tool_forwarder_connect(const cJSON *params);

// Forgets the fabric, its devices and the forwarder secret (the application's
// setup or factory reset). If Matter was running, the device restarts 2 s
// later (CHIP is held from here).
void chip_tool_forwarder_erase(void);

#ifdef __cplusplus
}
#endif
