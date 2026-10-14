// SPDX-License-Identifier: Apache-2.0

/* The stream's keys, from the per-gateway secret (mgw_proto.h): HMAC-SHA256
 * through CHIP's crypto. Each returns false on a crypto failure. */
#pragma once

#include "mgw_proto.h"

namespace mgw {

bool TlsPsk(const uint8_t * secret, size_t secretLen, uint8_t out[kKeyLen]);
// NUL-terminated, kIdentityLen bytes with the NUL.
bool TlsIdentity(const uint8_t * secret, size_t secretLen, char out[kIdentityLen]);
bool SessionSecret(const uint8_t connKey[kKeyLen], uint64_t node, uint16_t cloudLsid, uint16_t gwLsid, uint8_t out[kKeyLen]);
bool ConstantTimeEqual(const uint8_t * a, const uint8_t * b, size_t len);

} // namespace mgw
