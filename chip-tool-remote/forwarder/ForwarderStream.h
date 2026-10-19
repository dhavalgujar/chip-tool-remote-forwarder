// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <functional>
#include <string>
#include <vector>

/*
 * The stream to the forwarder (../core/ctf_proto.h):
 * one TCP connection, direct or through an HTTP CONNECT proxy, in TLS 1.2 (ECDHE-PSK) keyed
 * by the per-forwarder secret (a pre-shared key). It carries the Matter messages of the sessions the
 * forwarder ends, the forwarder's commands (call), its signing requests (sign) and
 * its events.
 *
 * Matter messages stay in the process (some sandboxes refuse UDP, even
 * on loopback): ForwarderClient's transport passes them to SendMatter(), and
 * inbound ones go to the Matter handler.
 *
 * Configuration (read once):
 *   CHIP_TOOL_REMOTE_CONNECT_FILE  matter.connect's payload, saved: {"endpoint": "host:port",
 *                             "secret": "<hex>", ...}
 *   CHIP_TOOL_REMOTE_TARGET               optional: "proxy" to reach that endpoint through the proxy, or
 *                             host:port / proxy:host:port to dial instead of it
 *   CHIP_TOOL_REMOTE_PROXY         proxy URL http://[user:pass@]host:port for proxy:
 *                             (default: HTTPS_PROXY, https_proxy, HTTP_PROXY, http_proxy)
 *
 * There is no automatic reconnect: Open() and Call() dial when the stream is
 * down. Epoch() counts connections and is 0 while down, so a session from an
 * older stream can be told apart.
 */
namespace ForwarderClient {

class ForwarderStream
{
public:
    enum class Result
    {
        kOk,
        kNotConfigured, // no CHIP_TOOL_REMOTE_CONNECT_FILE
        kNoStream,      // can't connect, or the stream dropped or timed out
        kRefused,       // the forwarder answered with an error (code)
    };

    // What the last error was about, for the hint chip-tool-remote prints
    // (ForwarderClient::NoteFailure).
    enum class Failure
    {
        kNone,
        kUnknownSecret, // the forwarder doesn't know this secret
        kProxyAuth,     // the CONNECT proxy wants other credentials (407)
        kProxyRefused,  // the CONNECT proxy refused the forwarder's address
        kOldProtocol,   // the forwarder speaks another protocol version, or no TLS
        kUnreachable,   // can't connect, or no answer
        kPolicy,        // the forwarder refused the node: not one it commissioned
        kOther,
    };

    static ForwarderStream & Instance();

    bool Configured();
    uint32_t Epoch();

    // One Matter message (as it would go over UDP) to the forwarder; false if
    // the stream is down.
    bool SendMatter(const uint8_t * msg, size_t len);
    // Matter messages from the forwarder; runs on the stream's reader thread.
    using MatterHandler = std::function<void(const uint8_t * msg, size_t len)>;
    void SetMatterHandler(MatterHandler handler);

    // A relay session for node: the forwarder's session ID and the session secret
    // (32 bytes), and the Epoch() of the connection it belongs to. On kRefused,
    // code is the forwarder's ErrCode.
    Result Open(uint64_t node, uint16_t cloudLsid, uint64_t cloudNode, uint16_t & fwdLsid, uint8_t secret[32], uint16_t & code,
                uint32_t & epoch);
    void Close(uint16_t cloudLsid, uint16_t fwdLsid);

    // Runs a forwarder command; out gets its result JSON.
    Result Call(const std::string & name, const std::string & params, unsigned timeoutS, std::string & out);

    // sign request (the body after the op byte) -> signed body (after the op
    // byte); empty for "no signer". Runs on a thread of its own.
    using SignHandler = std::function<std::vector<uint8_t>(const uint8_t * body, size_t len)>;
    void SetSignHandler(SignHandler handler);
    // event (kind, node); runs on the stream's reader thread: don't block.
    using EventHandler = std::function<void(uint8_t kind, uint64_t node)>;
    void SetEventHandler(EventHandler handler);

    // Last error text for logs (never contains the proxy URL or the secret),
    // and what it was about.
    std::string LastError();
    Failure LastFailure();

private:
    ForwarderStream() = default;
    struct Impl;
    Impl & I();
};

} // namespace ForwarderClient
