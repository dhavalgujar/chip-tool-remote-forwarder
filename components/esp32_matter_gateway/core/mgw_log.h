// SPDX-License-Identifier: Apache-2.0

// The relay's log lines (connections, sessions): MGW_LOG for progress, MGW_ERR
// for failures. Through ESP-IDF's log on the ESP32, where CHIP's own logs are
// at ERROR (devices/sdkconfig.matter-gateway), and through CHIP's logging on a
// host (mgw-host).
#pragma once

#if defined(ESP_PLATFORM)
#include "esp_log.h"
#define MGW_LOG(fmt, ...) ESP_LOGI("matter_gw", fmt, ##__VA_ARGS__)
#define MGW_ERR(fmt, ...) ESP_LOGE("matter_gw", fmt, ##__VA_ARGS__)
#else
#include <lib/support/logging/CHIPLogging.h>
#define MGW_LOG(fmt, ...) ChipLogProgress(AppServer, "mgw: " fmt, ##__VA_ARGS__)
#define MGW_ERR(fmt, ...) ChipLogError(AppServer, "mgw: " fmt, ##__VA_ARGS__)
#endif
