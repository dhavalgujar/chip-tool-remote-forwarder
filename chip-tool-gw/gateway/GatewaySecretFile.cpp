// SPDX-License-Identifier: Apache-2.0

#include "GatewaySecretFile.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace GatewayClient {

size_t ParseSecret(const uint8_t * raw, size_t n, uint8_t * out, size_t cap)
{
    size_t s = 0, e = n;
    while (s < e && isspace(raw[s]))
        s++;
    while (e > s && isspace(raw[e - 1]))
        e--;
    bool hex = e > s;
    for (size_t i = s; hex && i < e; i++)
        hex = isxdigit(raw[i]);
    size_t len = 0;
    if (hex)
    {
        // Hex: all of it, or nothing (an odd count is a typo, not raw bytes).
        if ((e - s) % 2 == 0 && (e - s) / 2 <= cap)
        {
            for (size_t i = s; i + 1 < e; i += 2)
            {
                char b[3]  = { static_cast<char>(raw[i]), static_cast<char>(raw[i + 1]), 0 };
                out[len++] = static_cast<uint8_t>(strtoul(b, nullptr, 16));
            }
        }
    }
    else if (n <= cap)
    {
        len = n;
        memcpy(out, raw, len);
    }
    return len;
}

size_t ReadSecretFile(const char * path, uint8_t * out, size_t cap)
{
    FILE * f = fopen(path, "rb");
    if (f == nullptr)
        return 0;
    uint8_t raw[257]; // one more than any secret file: a longer one is refused
    size_t n = fread(raw, 1, sizeof(raw), f);
    fclose(f);
    size_t len = n == sizeof(raw) ? 0 : ParseSecret(raw, n, out, cap);
    memset(raw, 0, sizeof(raw));
    return len;
}

} // namespace GatewayClient
