// SPDX-License-Identifier: Apache-2.0

// CHIP limits for the forwarder (devices/sdkconfig.chip-tool-forwarder:
// CONFIG_CHIP_PROJECT_CONFIG). The relay uses two secure sessions per device
// per cloud controller (the cloud's, keyed from the stream, and the forwarder's
// own CASE session); CHIP's default pool (MAX_FABRICS * 3 + 2 = 17) stops at
// about 8 devices. The pool is in SessionManager, heap-allocated (PSRAM with
// CHIP_MEM_ALLOC_MODE_EXTERNAL): 216 B per session.
#pragma once

#define CHIP_CONFIG_SECURE_SESSION_POOL_SIZE 128
#define CHIP_CONFIG_CONTROLLER_MAX_ACTIVE_CASE_CLIENTS 32
