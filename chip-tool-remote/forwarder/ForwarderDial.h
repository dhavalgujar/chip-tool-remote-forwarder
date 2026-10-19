// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdint.h>

#include <string>

#include "ForwarderStream.h"

/*
 * The stream's TCP connection: direct, or through an HTTP CONNECT proxy (how
 * a sandboxed VM reaches the home network, for example). The proxy comes from
 * CHIP_TOOL_REMOTE_PROXY, else HTTPS_PROXY, https_proxy, HTTP_PROXY or http_proxy:
 * http://[user:pass@]host:port. Its URL carries credentials, so nothing here
 * logs it or puts it in an error.
 */
namespace ForwarderClient {

// Splits host:port or [v6]:port. Without a port: defaultPort, or false if
// that is 0.
bool SplitHostPort(const std::string & s, std::string & host, uint16_t & port, uint16_t defaultPort);
// host:port, with brackets around an IPv6 host.
std::string HostPort(const std::string & host, uint16_t port);

// A TCP connection to host:port; -1 on failure.
int DialTcp(const std::string & host, uint16_t port, int timeoutMs);

// A TCP connection to target (host:port) through the CONNECT proxy, ready for
// TLS; -1 on failure, with why and what it was about.
int DialProxy(const std::string & target, int timeoutMs, std::string & why, ForwarderStream::Failure & kind);

} // namespace ForwarderClient
