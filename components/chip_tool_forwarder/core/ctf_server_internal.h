// SPDX-License-Identifier: Apache-2.0

// Between the server's parts (ctf_server.cpp, ctf_listener.cpp); not for
// callers of ctf_server.h.
#pragma once

#include <stdint.h>

#include "ctf_server.h"

namespace ctf {

// The configuration StartServer was given (the port and spawn don't change).
const ServerConfig & ServerSettings();
// A connection a listener accepted: starts its task, or closes fd (over the
// limits, or out of memory).
void StartConnection(int fd);
// A listener on the server's port, bound to ifname (null: any interface) and
// localIp (0: any); a handle for RemoveListener, or -1.
int OpenListener(const char * ifname, uint32_t localIp);

} // namespace ctf
