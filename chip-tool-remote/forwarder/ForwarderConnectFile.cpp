// SPDX-License-Identifier: Apache-2.0

#include "ForwarderConnectFile.h"

#include <ctype.h>
#include <stdlib.h>

#include <algorithm>
#include <fstream>
#include <iterator>
#include <memory>

#include <json/json.h>

#include "ctf_proto.h"

namespace ForwarderClient {

namespace {

void Wipe(std::string & s)
{
    std::fill(s.begin(), s.end(), '\0');
}

// Hex digits, an even count of them; 0 if malformed or longer than cap.
size_t ParseHex(const std::string & hx, uint8_t * out, size_t cap)
{
    if (hx.empty() || hx.size() % 2 != 0 || hx.size() / 2 > cap ||
        !std::all_of(hx.begin(), hx.end(), [](char c) { return isxdigit(static_cast<unsigned char>(c)) != 0; }))
        return 0;
    size_t len = 0;
    for (size_t i = 0; i + 1 < hx.size(); i += 2)
    {
        char b[3]  = { hx[i], hx[i + 1], 0 };
        out[len++] = static_cast<uint8_t>(strtoul(b, nullptr, 16));
    }
    return len;
}

} // namespace

bool ReadConnectFile(const std::string & path, const char * name, std::string & endpoint, uint8_t * secret, size_t cap,
                     size_t & len, std::string & why)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
    {
        why = std::string("can't read ") + name + " (" + path + ")";
        return false;
    }
    std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    Json::Value v;
    std::string err;
    std::unique_ptr<Json::CharReader> reader(Json::CharReaderBuilder().newCharReader());
    bool parsed = text.size() <= 16384 && reader->parse(text.data(), text.data() + text.size(), &v, &err);
    Wipe(text);
    if (!parsed || !v.isObject() || !v.isMember("endpoint") || !v["endpoint"].isString() || !v.isMember("secret") ||
        !v["secret"].isString())
    {
        why = std::string(name) + " must be matter.connect's payload: a JSON object with endpoint and secret";
        return false;
    }
    endpoint       = v["endpoint"].asString();
    std::string hx = v["secret"].asString();
    v              = Json::Value();
    len            = ParseHex(hx, secret, cap);
    Wipe(hx);
    if (len < ctf::kMinSecretLen)
    {
        why = std::string("the secret in ") + name + " must be 32-128 hex digits";
        return false;
    }
    return true;
}

} // namespace ForwarderClient
