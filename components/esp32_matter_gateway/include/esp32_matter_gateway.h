// SPDX-License-Identifier: Apache-2.0

// A Matter gateway for chip-tool-gw: chip-tool, wherever it runs, reaches the
// home's Matter devices through this device. esp32_matter_gateway_connect()
// gives the address and secret of a TLS stream (TCP 7401); chip-tool-gw sends
// Matter messages over it, and the device relays them onto its own CASE
// sessions with the devices, over Wi-Fi or Thread. The fabric's CA is
// chip-tool-gw's: the device enrolls once and asks chip-tool-gw to verify and
// sign every device it commissions.
//
// The application calls esp32_matter_gateway_init() at boot and offers
// esp32_matter_gateway_connect() to the controller's user on a channel it
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
    // Where chip-tool-gw connects from. NULL: every interface (the local
    // network). Otherwise the two-letter name of an lwIP netif (a tunnel, for
    // example "tn"): the listener is bound to that interface and to the Wi-Fi
    // station's address, opened once both exist and moved when the address
    // changes, and the port isn't open on the local network.
    const char *listen_netif;
} esp32_matter_gateway_config_t;

// At boot.
void esp32_matter_gateway_init(const esp32_matter_gateway_config_t *config);

// The application's setup finished in this boot: the device restarts a few
// seconds later, so that Matter starts.
void esp32_matter_gateway_setup_done(void);

// The stream's endpoint and secret, and the chip-tool-gw release to use
// (client), as {ok, payload} or {ok, error} JSON.
// params: {"rotate": true} replaces the secret first, closing every
// connection. The application's trusted channel only (see above).
cJSON *esp32_matter_gateway_connect(const cJSON *params);

// Forgets the fabric, its devices and the gateway secret (the application's
// setup or factory reset). If Matter was running, the device restarts 2 s
// later (CHIP is held from here).
void esp32_matter_gateway_erase(void);

#ifdef __cplusplus
}
#endif
