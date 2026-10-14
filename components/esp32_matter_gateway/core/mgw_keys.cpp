// SPDX-License-Identifier: Apache-2.0

#include "mgw_keys.h"

#include <string.h>

#include <crypto/CHIPCryptoPAL.h>

namespace mgw {

namespace {

bool Mac(const uint8_t * key, size_t keyLen, const uint8_t * msg, size_t msgLen, uint8_t out[kMacLen])
{
    chip::Crypto::HMAC_sha hmac;
    return hmac.HMAC_SHA256(key, keyLen, msg, msgLen, out, kMacLen) == CHIP_NO_ERROR;
}

bool MacLabel(const uint8_t * key, size_t keyLen, const char * label, uint8_t out[kMacLen])
{
    return Mac(key, keyLen, reinterpret_cast<const uint8_t *>(label), strlen(label), out);
}

} // namespace

bool TlsPsk(const uint8_t * secret, size_t secretLen, uint8_t out[kKeyLen])
{
    return MacLabel(secret, secretLen, "matter-gw tls psk", out);
}

bool TlsIdentity(const uint8_t * secret, size_t secretLen, char out[kIdentityLen])
{
    uint8_t id[kMacLen];
    if (!MacLabel(secret, secretLen, "matter-gw psk id", id))
    {
        return false;
    }
    static const char kHex[] = "0123456789abcdef";
    // kIdentityName + ':' + 16 hex digits
    constexpr size_t kPrefixLen = sizeof(kIdentityName);
    static_assert(kPrefixLen + 16 + 1 == kIdentityLen, "kIdentityLen: kIdentityName, ':', 16 hex digits, NUL");
    memcpy(out, kIdentityName, kPrefixLen - 1);
    out[kPrefixLen - 1] = ':';
    for (size_t i = 0; i < 8; i++)
    {
        out[kPrefixLen + 2 * i]     = kHex[id[i] >> 4];
        out[kPrefixLen + 2 * i + 1] = kHex[id[i] & 15];
    }
    out[kIdentityLen - 1] = 0;
    memset(id, 0, sizeof(id));
    return true;
}

bool SessionSecret(const uint8_t connKey[kKeyLen], uint64_t node, uint16_t cloudLsid, uint16_t gwLsid, uint8_t out[kKeyLen])
{
    static const char label[] = "matter-gw session";
    uint8_t msg[sizeof(label) - 1 + 8 + 2 + 2];
    memcpy(msg, label, sizeof(label) - 1);
    uint8_t * p = msg + sizeof(label) - 1;
    Put64(p, node);
    Put16(p + 8, cloudLsid);
    Put16(p + 10, gwLsid);
    return Mac(connKey, kKeyLen, msg, sizeof(msg), out);
}

bool ConstantTimeEqual(const uint8_t * a, const uint8_t * b, size_t len)
{
    return chip::Crypto::IsBufferContentEqualConstantTime(a, b, len);
}

} // namespace mgw
