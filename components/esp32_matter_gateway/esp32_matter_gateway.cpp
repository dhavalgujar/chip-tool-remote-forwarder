// SPDX-License-Identifier: Apache-2.0

// The component's entry points; see include/esp32_matter_gateway.h.
#include "esp32_matter_gateway.h"

#include <string.h>

#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include <esp_matter.h>
#include <platform/CHIPDeviceLayer.h>

#include "controller.h"
#include "gateway.h"
#include "mgw_cmd.h"
#include "mgw_nvs.h"
#include "thread_cmds.h"

#if !CONFIG_SPIRAM
#error "The Matter gateway needs a board with PSRAM (see examples/gateway/sdkconfig.defaults)"
#endif
#if CONFIG_NVS_ENCRYPTION
#error "The Matter gateway can't be combined with CONFIG_NVS_ENCRYPTION: this esp-matter version doesn't support the HMAC-based NVS encryption scheme"
#endif

#define TAG "matter_gw"

// Setup done while running: restart, so that Matter starts.
#define RESTART_AFTER_SETUP_MS 6000

namespace {

bool s_initialized;
bool s_running;

bool init_partition()
{
    esp_err_t err = nvs_flash_init_partition(MGW_NVS_PARTITION);
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        // Only Matter's partition: the firmware's own NVS is never erased.
        ESP_LOGW(TAG, "the \"%s\" NVS partition is unreadable (%s); erasing it", MGW_NVS_PARTITION, esp_err_to_name(err));
        nvs_flash_erase_partition(MGW_NVS_PARTITION);
        err = nvs_flash_init_partition(MGW_NVS_PARTITION);
    }
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "no \"%s\" NVS partition (%s): Matter stays off", MGW_NVS_PARTITION, esp_err_to_name(err));
        return false;
    }
    return true;
}

void restart_task(void * arg)
{
    vTaskDelay(pdMS_TO_TICKS(reinterpret_cast<uintptr_t>(arg)));
    ESP_LOGI(TAG, "restarting");
    esp_restart();
}

// Setup not done: whatever a previous owner left (a reset that lost power
// before its erase, or a setup cleared at boot) goes, so the next one starts
// clean.
void erase_if_used()
{
    nvs_stats_t st = {};
    if (nvs_get_stats(MGW_NVS_PARTITION, &st) == ESP_OK && st.used_entries == 0)
    {
        return;
    }
    nvs_flash_deinit_partition(MGW_NVS_PARTITION);
    esp_err_t err = nvs_flash_erase_partition(MGW_NVS_PARTITION);
    ESP_LOGI(TAG, "setup not done: a previous Matter fabric forgotten: %s", esp_err_to_name(err));
    nvs_flash_init_partition(MGW_NVS_PARTITION);
}


} // namespace

extern "C" void esp32_matter_gateway_init(const esp32_matter_gateway_config_t * config)
{
    if (s_initialized || config == nullptr)
    {
        return;
    }
    s_initialized = true;
    if (!init_partition())
    {
        return;
    }
    mgw_thread_register();
    mgw_ctl_register();
    mgw_register();
    if (!config->setup_complete)
    {
        erase_if_used();
        ESP_LOGI(TAG, "setup not done: Matter starts on the first boot after it");
        return;
    }
    mgw_thread_start();
    mgw_ctl_start();
    mgw_start(config->listen_netif);
    s_running = true;
}

extern "C" void esp32_matter_gateway_setup_done(void)
{
    if (!s_initialized || s_running)
    {
        return;
    }
    ESP_LOGI(TAG, "setup done: restarting in %d s to start Matter", RESTART_AFTER_SETUP_MS / 1000);
    if (xTaskCreate(restart_task, "matter_restart", 2048, reinterpret_cast<void *>(RESTART_AFTER_SETUP_MS), 3, nullptr) !=
        pdPASS)
    {
        ESP_LOGW(TAG, "no restart task; Matter starts on the next boot");
    }
}

extern "C" cJSON * esp32_matter_gateway_connect(const cJSON * params)
{
    if (!s_initialized)
    {
        return mgw_result_err("matter_unavailable", "%s", "Matter isn't set up on this device");
    }
    const cJSON * rotate = params ? cJSON_GetObjectItemCaseSensitive(params, "rotate") : nullptr;
    if (rotate != nullptr && !cJSON_IsNull(rotate) && !cJSON_IsBool(rotate))
    {
        return mgw_result_err("invalid_param", "%s", "rotate must be boolean");
    }
    cJSON * r = mgw_connect(cJSON_IsTrue(rotate));
    ESP_LOGI(TAG, "matter.connect: %s", mgw_result_is_ok(r) ? "ok" : "error");
    return r;
}

extern "C" void esp32_matter_gateway_erase(void)
{
    // CHIP is held off for good (the device restarts next), so nothing it
    // stores lands after the erase.
    if (esp_matter::is_started())
    {
        chip::DeviceLayer::PlatformMgr().LockChipStack();
    }
    esp_err_t err = nvs_flash_erase_partition(MGW_NVS_PARTITION);
    ESP_LOGI(TAG, "Matter fabric, devices and gateway secret forgotten: %s", esp_err_to_name(err));
    if (s_running)
    {
        // Not every reset path restarts (an unpair does not); CHIP is held,
        // so Matter can only come back after one.
        xTaskCreate(restart_task, "matter_restart", 2048, reinterpret_cast<void *>(2000), 3, nullptr);
    }
}
