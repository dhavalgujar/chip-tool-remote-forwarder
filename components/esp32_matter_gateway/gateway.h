// SPDX-License-Identifier: Apache-2.0

// The gateway: cloud controllers (chip-tool-gw) reach the devices this gateway
// commissioned through sessions it ends; see core/mgw_relay.h and
// core/mgw_proto.h. TCP port mgw::kDefaultPort (7401), on one interface or
// all (esp32_matter_gateway_config_t), with a per-device secret that
// esp32_matter_gateway_connect() hands out on the application's channel.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

// The stream commands (matter.gateway_status, and the CA's matter.enroll);
// before Matter starts.
void mgw_register(void);
// The stream server, once the controller runs (boots after setup only).
// listen_netif: see esp32_matter_gateway_config_t.
void mgw_start(const char * listen_netif);
// esp32_matter_gateway_connect(): the stream's endpoint and secret; rotate
// replaces the secret first and closes every connection.
cJSON * mgw_connect(bool rotate);
// Queues a control frame for one stream connection (any task; the CHIP thread
// must not block on a socket). False if it can't be queued.
bool mgw_send_later(uint32_t conn, const uint8_t * body, size_t len);

#ifdef __cplusplus
}
#endif
