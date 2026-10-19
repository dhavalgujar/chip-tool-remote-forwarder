// SPDX-License-Identifier: Apache-2.0

// The relay's log lines (connections, sessions): CTF_LOG for progress, CTF_ERR
// for failures. Through ESP-IDF's log on the ESP32, where CHIP's own logs are
// at ERROR (devices/sdkconfig.chip-tool-forwarder), and through CHIP's logging on a
// host (forwarder-host).
#pragma once

#if defined(ESP_PLATFORM)
#include "esp_log.h"
#define CTF_LOG(fmt, ...) ESP_LOGI("ctf", fmt, ##__VA_ARGS__)
#define CTF_ERR(fmt, ...) ESP_LOGE("ctf", fmt, ##__VA_ARGS__)
#else
#include <lib/support/logging/CHIPLogging.h>
#define CTF_LOG(fmt, ...) ChipLogProgress(AppServer, "ctf: " fmt, ##__VA_ARGS__)
#define CTF_ERR(fmt, ...) ChipLogError(AppServer, "ctf: " fmt, ##__VA_ARGS__)
#endif
