// SPDX-License-Identifier: Apache-2.0

/*
 * Matter gateway stream server: accepts cloud
 * controllers over TCP and TLS with the per-gateway secret (mgw_proto.h,
 * mgw_tls.h), opens relay sessions, and bridges each connection's Matter
 * messages to the local CHIP stack through a loopback UDP socket (so the stack
 * sees an ordinary UDP peer, 127.0.0.1:port).
 *
 * POSIX sockets (Linux or lwIP); one thread or task per connection.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "mgw_proto.h"

namespace mgw {

struct ServerConfig
{
    uint16_t port        = kDefaultPort; // TCP, IPv4
    // A listener on all interfaces. False: only the ones AddListener adds
    // (bound to an interface, e.g. the gateway's tunnel).
    bool anyAddress      = true;
    uint16_t chipUdpPort = 0;    // the CHIP stack's UDP port on this host
    int maxConnections   = 4;
    uint8_t secret[kMaxSecretLen];
    size_t secretLen = 0;
    // Starts fn(arg) on a new thread/task (stack in bytes, a hint).
    // False if it can't (no memory): the caller then cleans up arg.
    bool (*spawn)(void (*fn)(void *), void * arg, const char * name, size_t stack) = nullptr;
    // Runs a gateway command (name, params JSON), writing its result JSON
    // ({ok, payload | error}) into out; called on a task of its own, so it
    // may take minutes (commissioning). Null: no gateway commands here.
    void (*call)(const char * name, const char * params, char * out, size_t cap) = nullptr;
    // Memory for connections and frame buffers (null: malloc/free); on the
    // ESP32, PSRAM keeps internal RAM for the radio and the TLS session.
    void * (*alloc)(size_t size) = nullptr;
    void (*release)(void * p)    = nullptr;
};

struct ServerStats
{
    uint32_t accepted;
    uint32_t refused; // over maxConnections
    uint32_t authFailures;
    uint32_t active;
    uint32_t framesIn;
    uint32_t framesOut;
    uint32_t badFrames;
};

// Starts the server (once), listening on all interfaces if anyAddress. False
// if that socket can't be set up.
bool StartServer(const ServerConfig & config);
// A listener on the server's port, bound to ifname (e.g. a tunnel that
// appears after StartServer) and to localIp (IPv4, network order; 0: any).
// lwIP allows one listener per address and port whatever the interface, so
// a second interface needs a specific address: the one its clients dial.
// Returns a handle for RemoveListener, or -1.
int AddListener(const char * ifname, uint32_t localIp);
// Stops that listener within about a second; its connections stay.
void RemoveListener(int handle);
// Replaces the secret for new handshakes (connections already up keep going).
void SetServerSecret(const uint8_t * secret, size_t len);
ServerStats GetServerStats();
bool ServerRunning();

// Runs fn(arg) on the CHIP thread and waits for it to return.
void RunInChipTask(void (*fn)(void *), void * arg);

// Inside ServerConfig::call: the connection the command came from (0 outside).
uint32_t CurrentCallConnection();
// Sends a frame to one connection (false if it's gone).
bool SendToConnection(uint32_t conn, uint8_t type, const uint8_t * body, size_t len);
// Sends a frame to every authenticated connection; returns how many took it.
// Blocking socket writes: not from the CHIP thread.
size_t SendToAllConnections(uint8_t type, const uint8_t * body, size_t len);
// An event control frame (mgw_proto.h `event`) to every connection.
size_t SendEvent(uint8_t kind, uint64_t node);
// Closes every authenticated connection (e.g. after the secret changed);
// returns how many. A handshake still in progress with the old secret is
// refused when it completes (SetServerSecret bumps the secret's generation).
size_t DisconnectAll();
// Called (on the connection's thread) with the body of a `signed` control
// frame after the op byte.
using SignedHandler = void (*)(uint32_t conn, const uint8_t * body, size_t len);
void SetSignedHandler(SignedHandler handler);

} // namespace mgw
