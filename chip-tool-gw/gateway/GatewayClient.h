// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <controller/CHIPDeviceController.h>

#include "GatewayStream.h"

/*
 * Gateway mode: every node is reached through a gateway that ends the node's
 * sessions. Active when MATTER_GW_CONNECT_FILE is set (see GatewayStream.h).
 *
 * Sessions (GatewaySessions.cpp): Install() sets CHIP's session lookup hook
 * (process wide, before the stack starts): whenever a session to a node is
 * looked up (a command, a resubscription), Ensure() gets one from the gateway
 * and puts it in the session table, so the lookup finds it and no CASE
 * handshake runs. A session from an older stream (the gateway restarted, the
 * stream dropped) is replaced.
 *
 * Signer (GatewaySigner.cpp): this controller's fabric CA verifies and signs
 * for the gateway while a gateway call runs.
 */
namespace GatewayClient {

bool Enabled();
void Install();
CHIP_ERROR Ensure(chip::FabricIndex fabric, chip::NodeId node);

// The call's commissioner, whose attestation verifier checks the devices and
// whose CA signs them; the gateway's own (controller) certificate only when
// enrolling (matter.enroll). nullptr: nothing is signed.
void SetSigner(chip::Controller::DeviceCommissioner * commissioner, bool enrolling);

// Why the last session or gateway call failed, with what to do about it
// ("" if nothing failed): chip-tool-gw prints it as its last line, since
// CHIP's own error ("Connection aborted") doesn't say.
void NoteFailure(const std::string & reason, GatewayStream::Failure kind);
std::string LastFailure();

} // namespace GatewayClient
