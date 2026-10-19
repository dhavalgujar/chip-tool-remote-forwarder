// SPDX-License-Identifier: Apache-2.0

/* The fabric's CA in the cloud; see forwarder_ca.cpp. */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "ctf_cmd.h"

// Installs the credentials issuer (before the Matter controller starts) and
// registers matter.enroll.
void ctf_ca_init(void);
// The connection whose forwarder command (commissioning) may ask the signer; 0: none.
void ctf_ca_set_signer_conn(uint32_t conn);
// Drops the device signing request in progress, if any (its answer will be
// ignored); before the commissioning that asked for it is stopped.
void ctf_ca_cancel_in_chip_task(void);
bool ctf_ca_enrolled(void);

#ifdef __cplusplus
namespace chip {
namespace Controller {
class DeviceCommissioner;
}
} // namespace chip
// Makes the cloud controller's verifier the commissioner's attestation
// verifier (CHIP thread, once the commissioner runs).
void ctf_ca_install_verifier(chip::Controller::DeviceCommissioner * commissioner);
#endif
