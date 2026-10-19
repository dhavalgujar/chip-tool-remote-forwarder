# SPDX-License-Identifier: Apache-2.0

idf_component_register(
    SRCS "main.c"
    PRIV_REQUIRES chip_tool_forwarder console esp_event esp_netif esp_wifi nvs_flash
)
