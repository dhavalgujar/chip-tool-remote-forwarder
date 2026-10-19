// SPDX-License-Identifier: Apache-2.0

/* Thread devices behind the home's Thread Border Router (the device itself
 * never uses 802.15.4):
 *   thread.set_dataset {dataset}   the TBR's active operational dataset (hex)
 *   thread.status [{address}]      dataset's public fields, IPv6 addresses,
 *                                  route to an address
 *   thread.clear_dataset
 * plus router re-solicitation, so the TBR's Route Information Option (the
 * OMR prefix, installed by CHIP's route hook) arrives at once after boot. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CTF_THREAD_DATASET_MAX 254

typedef struct {
    char network_name[17];
    int channel;      /* -1 if absent */
    int pan_id;       /* -1 if absent */
    char ext_pan_id[17];
    char mesh_local[48];
} ctf_thread_info_t;

/* Check that `tlvs` is an active operational dataset a device can join
 * (active timestamp, channel, PAN ID, extended PAN ID, network key, mesh-local
 * prefix), and fill `info` with its public fields. Returns NULL if valid,
 * else a reason. Host-testable. */
const char *ctf_thread_dataset_check(const uint8_t *tlvs, size_t len, ctf_thread_info_t *info);
/* Hex (optionally "hex:"-prefixed, whitespace ignored) to bytes; -1 on error. */
int ctf_thread_hex_decode(const char *hex, uint8_t *out, size_t out_max);

/* The stored dataset (for commissioning Thread devices). false if none. */
bool ctf_thread_dataset_get(uint8_t *tlvs, size_t *len);

/* Register the thread.* commands. */
void ctf_thread_register(void);
/* Router re-solicitation after IPv6 address events (with Matter). */
void ctf_thread_start(void);

#ifdef __cplusplus
}
#endif
