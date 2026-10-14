// SPDX-License-Identifier: Apache-2.0

// The per-gateway secret the stream's TLS keys come from (core/mgw_keys.h):
// kept in the matter NVS partition, with a RAM copy so that commands never
// read flash. esp32_matter_gateway_connect() hands it out.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// The stored secret, or a new random one (stored) when there is none; out
// gets it (cap >= mgw::kMaxSecretLen). Returns its length.
size_t mgw_secret_ensure(uint8_t * out, size_t cap);
// Replaces the secret (stored, then served) and closes every connection.
// Returns how many were closed, or SIZE_MAX if the new one couldn't be stored.
size_t mgw_secret_rotate(void);
bool mgw_secret_is_set(void);
// The secret as lower-case hex (cap >= 2 * mgw::kMaxSecretLen + 1); false if
// there is none yet.
bool mgw_secret_hex(char * out, size_t cap);
