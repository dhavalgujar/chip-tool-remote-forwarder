// SPDX-License-Identifier: Apache-2.0

/*
 * TLS for the forwarder stream (ctf_proto.h): TLS 1.2 only, ECDHE-PSK with
 * AES-128-CBC-SHA256 (P-256), encrypt-then-MAC, the extended master secret,
 * 4 KB records (max_fragment_length), ALPN kAlpn, no tickets or
 * renegotiation. TLS 1.2 rather than 1.3: the record size can be negotiated
 * with a pre-shared key (OpenSSL refuses max_fragment_length with a TLS 1.3
 * external PSK), so each forwarder connection keeps ~4 KB buffers instead of
 * 16 KB ones, and the firmware needs no TLS 1.3 code.
 *
 * Two implementations: ctf_tls_mbedtls.cpp (ESP32, the server) and
 * ctf_tls_openssl.cpp (host: chip-tool-remote's client, forwarder-host's server).
 *
 * A Tls is used from several threads: one reader, any number of writers.
 * Reads and writes are serialised inside (neither library allows them at once
 * on one context); each TlsWrite sends its bytes whole, never interleaved with
 * another writer's. The socket is the caller's: it is non-blocking once the
 * handshake is done, and TlsFree doesn't close it.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "ctf_proto.h"

namespace ctf {

struct Tls;

enum class TlsFail
{
    kNone,
    kUnknownSecret, // server: the client's PSK identity isn't ours; client: refused (no PSK in common)
    kProtocol,      // ALPN: the other end speaks another version of the stream
    kClosed,        // the connection closed or reset during the handshake
    kNotTls,        // client: the forwarder answered with something other than TLS
    kTimeout,
    kOther,
};

// Server: given the client's PSK identity, writes the PSK (kKeyLen bytes) and
// returns true, or false for an unknown identity.
using TlsPskLookup = bool (*)(void * ctx, const uint8_t * identity, size_t len, uint8_t psk[kKeyLen]);

// The handshake on a connected socket, within timeoutMs. nullptr on failure;
// why says what failed (detail, if given, gets a short library error text).
Tls * TlsAccept(int fd, TlsPskLookup lookup, void * ctx, uint32_t timeoutMs, TlsFail & why, char * detail = nullptr,
                size_t detailCap = 0);
Tls * TlsConnect(int fd, const uint8_t psk[kKeyLen], const char * identity, uint32_t timeoutMs, TlsFail & why,
                 char * detail = nullptr, size_t detailCap = 0);

constexpr int kTlsAgain = -1; // nothing to read now
constexpr int kTlsError = -2;
// >0: bytes read; 0: the other end closed; kTlsAgain; kTlsError.
int TlsRead(Tls * t, uint8_t * buf, size_t cap);
// Decrypted bytes waiting to be read (poll() won't see them).
bool TlsPending(Tls * t);
// All of buf, or false (error, or not writable for timeoutMs).
bool TlsWrite(Tls * t, const uint8_t * buf, size_t len, uint32_t timeoutMs);
// conn_key: the TLS exporter, label kExportLabel, no context.
bool TlsExportConnKey(Tls * t, uint8_t out[kKeyLen]);
void TlsFree(Tls * t);

} // namespace ctf
