// SPDX-License-Identifier: Apache-2.0

// The forwarder: cloud controllers (chip-tool-remote) reach the devices this forwarder
// commissioned through sessions it ends; see core/ctf_relay.h and
// core/ctf_proto.h. TCP port ctf::kDefaultPort (7401), on one interface or
// all (chip_tool_forwarder_config_t), with a per-device secret that
// chip_tool_forwarder_connect() hands out on the application's channel.
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
void ctf_register(void);
// The stream server, once the controller runs (boots after setup only).
// listen_netif: see chip_tool_forwarder_config_t.
void ctf_start(const char * listen_netif);
// chip_tool_forwarder_connect(): the stream's endpoint and secret; rotate
// replaces the secret first and closes every connection.
cJSON * ctf_connect(bool rotate);
// Queues a control frame for one stream connection (any task; the CHIP thread
// must not block on a socket). False if it can't be queued.
bool ctf_send_later(uint32_t conn, const uint8_t * body, size_t len);

#ifdef __cplusplus
}
#endif
