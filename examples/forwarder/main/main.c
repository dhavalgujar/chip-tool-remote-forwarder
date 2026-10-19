// SPDX-License-Identifier: Apache-2.0

// The forwarder without an application around it: the device joins the
// Wi-Fi set in menuconfig, Bluetooth is CHIP's from boot, and chip-tool-remote
// connects from the local network. The console's `connect` prints what
// chip-tool-remote needs (connect.json for chip-tool-remote/chip-tool-remote.sh); in an application
// of your own, offer it only on a channel you trust, never on the network.
#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "esp_console.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include "chip_tool_forwarder.h"

#define TAG "example"

static void on_wifi(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (id == WIFI_EVENT_STA_START || id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
    } else if (id == WIFI_EVENT_STA_CONNECTED) {
        esp_netif_create_ip6_linklocal((esp_netif_t *)arg);
    }
}

static void start_wifi(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t *sta = esp_netif_create_default_wifi_sta();
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi, sta));
    wifi_config_t cfg = {0};
    snprintf((char *)cfg.sta.ssid, sizeof(cfg.sta.ssid), "%s", CONFIG_EXAMPLE_WIFI_SSID);
    snprintf((char *)cfg.sta.password, sizeof(cfg.sta.password), "%s", CONFIG_EXAMPLE_WIFI_PASSWORD);
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
}

// connect [--rotate] [--secret]: the stream's endpoint and secret (hidden
// unless --secret).
static int connect_cmd(int argc, char **argv)
{
    bool rotate = false, show = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--rotate") == 0) {
            rotate = true;
        } else if (strcmp(argv[i], "--secret") == 0) {
            show = true;
        } else {
            printf("usage: connect [--rotate] [--secret]\n");
            return 1;
        }
    }
    cJSON *params = cJSON_CreateObject();
    cJSON_AddBoolToObject(params, "rotate", rotate);
    cJSON *r = chip_tool_forwarder_connect(params);
    cJSON_Delete(params);
    cJSON *payload = cJSON_GetObjectItemCaseSensitive(r, "payload");
    if (!show && cJSON_GetObjectItemCaseSensitive(payload, "secret")) {
        cJSON_ReplaceItemInObject(payload, "secret", cJSON_CreateString("(hidden: connect --secret)"));
    }
    char *text = cJSON_PrintUnformatted(r);
    printf("%s\n", text ? text : "{}");
    cJSON_free(text);
    cJSON_Delete(r);
    return 0;
}

// erase: forget the fabric, its devices and the secret (restarts).
static int erase_cmd(int argc, char **argv)
{
    chip_tool_forwarder_erase();
    return 0;
}

static void start_console(void)
{
    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    config.prompt = "forwarder>";
#if CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
    esp_console_dev_usb_serial_jtag_config_t dev = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_usb_serial_jtag(&dev, &config, &repl));
#else
    esp_console_dev_uart_config_t dev = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&dev, &config, &repl));
#endif
    const esp_console_cmd_t cmds[] = {
        {.command = "connect", .help = "The endpoint and secret chip-tool-remote connects with", .func = connect_cmd},
        {.command = "erase", .help = "Forget the Matter fabric, its devices and the secret", .func = erase_cmd},
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        ESP_ERROR_CHECK(esp_console_cmd_register(&cmds[i]));
    }
    ESP_ERROR_CHECK(esp_console_start_repl(repl));
}

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    if (strlen(CONFIG_EXAMPLE_WIFI_SSID) == 0) {
        ESP_LOGW(TAG, "no Wi-Fi set (menuconfig: forwarder example)");
    }
    start_wifi();
    // No setup of its own: Bluetooth is CHIP's from boot, and chip-tool-remote
    // connects from the local network.
    const chip_tool_forwarder_config_t forwarder = {.setup_complete = true, .listen_netif = NULL};
    chip_tool_forwarder_init(&forwarder);
    start_console();
}
