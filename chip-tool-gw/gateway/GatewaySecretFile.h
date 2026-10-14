// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace GatewayClient {

// A gateway secret: hex digits (an even count, whitespace around them
// allowed), or raw bytes. Returns the length; 0 if malformed or longer than
// cap.
size_t ParseSecret(const uint8_t * raw, size_t n, uint8_t * out, size_t cap);

// Reads a gateway secret file (ParseSecret); 0 also if unreadable: mgw-host's
// secret (gateway serve SECRET-FILE).
size_t ReadSecretFile(const char * path, uint8_t * out, size_t cap);

} // namespace GatewayClient
