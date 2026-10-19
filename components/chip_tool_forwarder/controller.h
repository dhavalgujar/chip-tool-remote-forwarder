// SPDX-License-Identifier: Apache-2.0

/* The forwarder's Matter controller (esp-matter's commissioner, no Matter server):
 * it commissions devices for a cloud controller (chip-tool-remote, which verifies
 * their attestation and signs their certificates) and holds the CASE sessions
 * the relay uses. Commands, over the forwarder stream:
 *   matter.commission {code, node_id?, network?, wifi_ssid?, wifi_password?, thread_dataset?, label?}
 *   matter.nodes, matter.rename {node_id, label}, matter.remove {node_id, forget?},
 *   matter.open_window {node_id, timeout_s?},
 *   matter.commissionables {timeout_s?}, matter.icd, matter.icd_wait
 * One commissioning, removal, window or discovery at a time; a second gets "busy". */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Register the matter.* commands, then start (boots after setup only). */
void ctf_ctl_register(void);
void ctf_ctl_start(void);

/* True if node_id is one this controller commissioned (matter.nodes). */
bool ctf_ctl_node_known(uint64_t node_id);

/* Called on the CHIP thread when a sleepy device (an ICD registered with this
 * controller) checks in: it is awake now. Keep it short; don't block. */
void ctf_ctl_set_icd_listener(void (*fn)(uint64_t node_id));

#ifdef __cplusplus
}
#endif
