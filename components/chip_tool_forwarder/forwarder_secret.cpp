// SPDX-License-Identifier: Apache-2.0

#include "forwarder_secret.h"

#include <mutex>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "ctf_nvs.h"

#include "ctf_proto.h"
#include "ctf_server.h"

#define TAG "ctf"
#define NVS_KEY "secret"

namespace {

constexpr size_t kNewSecretLen = 32;

std::mutex s_lock;
uint8_t s_secret[ctf::kMaxSecretLen];
size_t s_len = 0;

size_t load(uint8_t * out, size_t cap)
{
    nvs_handle_t h;
    size_t len = cap;
    if (ctf_nvs_open(NVS_READONLY, &h) != ESP_OK)
    {
        return 0;
    }
    if (nvs_get_blob(h, NVS_KEY, out, &len) != ESP_OK)
    {
        len = 0;
    }
    nvs_close(h);
    return len;
}

esp_err_t store(const uint8_t * secret, size_t len)
{
    nvs_handle_t h;
    esp_err_t err = ctf_nvs_open(NVS_READWRITE, &h);
    if (err == ESP_OK)
    {
        err = nvs_set_blob(h, NVS_KEY, secret, len);
        if (err == ESP_OK)
        {
            err = nvs_commit(h);
        }
        nvs_close(h);
    }
    return err;
}

void keep(const uint8_t * secret, size_t len)
{
    std::lock_guard<std::mutex> l(s_lock);
    memset(s_secret, 0, sizeof(s_secret));
    memcpy(s_secret, secret, len);
    s_len = len;
}

} // namespace

size_t ctf_secret_ensure(uint8_t * out, size_t cap)
{
    size_t len = load(out, cap);
    if (len < ctf::kMinSecretLen)
    {
        len = kNewSecretLen;
        esp_fill_random(out, len);
        esp_err_t err = store(out, len);
        ESP_LOGW(TAG, "no forwarder secret: generated one (%s); the application hands it out (chip_tool_forwarder_connect)",
                 err == ESP_OK ? "stored" : esp_err_to_name(err));
    }
    keep(out, len);
    return len;
}

size_t ctf_secret_rotate(void)
{
    uint8_t secret[kNewSecretLen];
    esp_fill_random(secret, sizeof(secret));
    esp_err_t err = store(secret, sizeof(secret));
    if (err != ESP_OK)
    {
        memset(secret, 0, sizeof(secret));
        ESP_LOGE(TAG, "secret not rotated: %s", esp_err_to_name(err));
        return SIZE_MAX;
    }
    ctf::SetServerSecret(secret, sizeof(secret));
    keep(secret, sizeof(secret));
    memset(secret, 0, sizeof(secret));
    size_t closed = ctf::DisconnectAll();
    ESP_LOGW(TAG, "forwarder secret rotated; %u connection(s) closed", (unsigned) closed);
    return closed;
}

bool ctf_secret_is_set(void)
{
    std::lock_guard<std::mutex> l(s_lock);
    return s_len >= ctf::kMinSecretLen;
}

bool ctf_secret_hex(char * out, size_t cap)
{
    std::lock_guard<std::mutex> l(s_lock);
    if (s_len == 0 || cap < 2 * s_len + 1)
    {
        return false;
    }
    for (size_t i = 0; i < s_len; i++)
    {
        snprintf(out + 2 * i, 3, "%02x", s_secret[i]);
    }
    return true;
}
