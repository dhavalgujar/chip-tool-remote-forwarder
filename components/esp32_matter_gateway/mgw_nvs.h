// SPDX-License-Identifier: Apache-2.0

// The gateway's own NVS data (the secret, the enrollment, the devices, the
// Thread dataset): one namespace, in the matter partition with CHIP's, so a
// setup reset that erases the partition forgets all of it.
#pragma once

#include "nvs.h"

#define MGW_NVS_PARTITION "matter"
#define MGW_NVS_NAMESPACE "matter_gw"

static inline esp_err_t mgw_nvs_open(nvs_open_mode_t mode, nvs_handle_t *handle)
{
    return nvs_open_from_partition(MGW_NVS_PARTITION, MGW_NVS_NAMESPACE, mode, handle);
}
