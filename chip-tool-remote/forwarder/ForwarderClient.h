// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <controller/CHIPDeviceController.h>

#include "ForwarderStream.h"

/*
 * Forwarder mode: every node is reached through a forwarder that ends the node's
 * sessions. Active when CHIP_TOOL_REMOTE_CONNECT_FILE is set (see ForwarderStream.h).
 *
 * Sessions (ForwarderSessions.cpp): Install() sets CHIP's session lookup hook
 * (process wide, before the stack starts): whenever a session to a node is
 * looked up (a command, a resubscription), Ensure() gets one from the forwarder
 * and puts it in the session table, so the lookup finds it and no CASE
 * handshake runs. A session from an older stream (the forwarder restarted, the
 * stream dropped) is replaced.
 *
 * Signer (ForwarderSigner.cpp): this controller's fabric CA verifies and signs
 * for the forwarder while a forwarder call runs.
 */
namespace ForwarderClient {

bool Enabled();
void Install();
CHIP_ERROR Ensure(chip::FabricIndex fabric, chip::NodeId node);

// The call's commissioner, whose attestation verifier checks the devices and
// whose CA signs them; the forwarder's own (controller) certificate only when
// enrolling (matter.enroll). nullptr: nothing is signed.
void SetSigner(chip::Controller::DeviceCommissioner * commissioner, bool enrolling);

// Why the last session or forwarder call failed, with what to do about it
// ("" if nothing failed): chip-tool-remote prints it as its last line, since
// CHIP's own error ("Connection aborted") doesn't say.
void NoteFailure(const std::string & reason, ForwarderStream::Failure kind);
std::string LastFailure();

} // namespace ForwarderClient
