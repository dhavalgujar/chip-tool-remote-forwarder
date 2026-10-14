// SPDX-License-Identifier: Apache-2.0

/* The controller's files among themselves. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"
#include "controller.h"

/* controller.cpp */
bool mgw_ctl_started(void);
cJSON *mgw_ctl_not_started(void);              /* the error while it isn't */
cJSON *mgw_ctl_unknown_node(uint64_t node);    /* the error for a node not in the list */
/* Runs fn on the CHIP thread with a 64-bit node ID (intptr_t is 32 bits on
 * these chips); fn takes it back with mgw_ctl_take_node(). */
bool mgw_ctl_schedule_node(void (*fn)(intptr_t), uint64_t node);
uint64_t mgw_ctl_take_node(intptr_t arg);
/* CHIP reported SecurePairingFailed for the current commissioning (CHIP thread). */
void mgw_ctl_pairing_failed(void);

/* controller_queue_filter.cpp: caps what CHIP queues from the network (CHIP thread) */
void mgw_ctl_install_queue_filter(void);

/* controller_icd.cpp */
void mgw_ctl_icd_register(void);
void mgw_ctl_icd_setup_in_chip_task(void);      /* once the controller runs (CHIP thread) */
#ifdef __cplusplus
namespace chip {
namespace Controller {
class CommissioningParameters;
class DevicePairingDelegate;
} // namespace Controller
} // namespace chip
/* Before each commissioning (CHIP thread): adds the ICD registration to params
 * and returns the pairing delegate to register for it. */
chip::Controller::DevicePairingDelegate *mgw_ctl_icd_prepare_commission(chip::Controller::CommissioningParameters &params);
#endif
void mgw_ctl_icd_forget(uint64_t node);    /* the node left the list (any task) */
/* A commissioning the watchdog stopped (CHIP thread): drops the ICD entry and
 * key it may have stored already. */
void mgw_ctl_icd_abort_in_chip_task(uint64_t node);
/* After a commissioning: true (once) if the device registered as an ICD but
 * its key could not be stored, so its Check-Ins will be dropped. */
bool mgw_ctl_icd_take_store_failure(void);
