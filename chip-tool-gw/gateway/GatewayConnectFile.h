// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>

namespace GatewayClient {

// Reads matter.connect's payload, as saved: {"endpoint": "host:port",
// "secret": "<hex>", ...}. chip-tool-gw's MATTER_GW_CONNECT_FILE, and
// mgw-host's gateway serve CONNECT-FILE. On failure, why says what is wrong,
// naming the file as name.
bool ReadConnectFile(const std::string & path, const char * name, std::string & endpoint, uint8_t * secret, size_t cap,
                     size_t & len, std::string & why);

} // namespace GatewayClient
