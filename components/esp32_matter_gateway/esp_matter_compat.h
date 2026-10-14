// SPDX-License-Identifier: Apache-2.0

// Force-included into esp-matter's pairing_command.cpp only (CMakeLists.txt):
// it names PeerAddress unqualified, which builds only with CHIP's commissioner
// discovery, not built here.
#pragma once

#ifdef __cplusplus
#include <transport/raw/PeerAddress.h>
using chip::Transport::PeerAddress;
#endif
