// SPDX-License-Identifier: Apache-2.0

// mgw_tls.h on mbedTLS 4 (ESP-IDF): the gateway's server side.
#define MBEDTLS_ALLOW_PRIVATE_ACCESS // the session's EtM and fragment length, checked after the handshake
#include "mgw_tls.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>

#include <chrono>
#include <mutex>
#include <new>

#include "sdkconfig.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_ciphersuites.h"

#if !defined(MBEDTLS_SSL_PROTO_TLS1_2) || !defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED) ||                                 \
    !defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT) || !defined(MBEDTLS_SSL_ALPN) || !defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH) ||  \
    !defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC) || !defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
#error "The Matter gateway needs TLS 1.2 with CONFIG_MBEDTLS_PSK_MODES (ECDHE-PSK), CONFIG_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT, ALPN and max fragment length"
#endif
#if !defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH) && !defined(CONFIG_MBEDTLS_DYNAMIC_BUFFER)
#warning "without CONFIG_MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH (or dynamic buffers) each gateway connection keeps 16 KB record buffers"
#endif

namespace mgw {

struct Tls
{
    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;
    int fd = -1;
    std::mutex io; // mbedtls_ssl_read / mbedtls_ssl_write
    std::mutex wr; // one TlsWrite at a time
    // handshake only
    TlsPskLookup lookup  = nullptr;
    void * lookupCtx     = nullptr;
    bool unknownIdentity = false;
};

namespace {

using Clock = std::chrono::steady_clock;

const int kSuites[]       = { MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, 0 };
const uint16_t kGroups[]  = { MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, MBEDTLS_SSL_IANA_TLS_GROUP_NONE };
const char * const kAlpns[] = { kAlpn, nullptr };

int MsLeft(Clock::time_point deadline)
{
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    return ms < 0 ? 0 : static_cast<int>(ms);
}

// Waits for the socket to be readable (or writable); false on a timeout.
bool Wait(int fd, bool write, int ms)
{
    fd_set s;
    FD_ZERO(&s);
    FD_SET(fd, &s);
    timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    return select(fd + 1, write ? nullptr : &s, write ? &s : nullptr, nullptr, &tv) > 0;
}

int BioSend(void * p, const unsigned char * buf, size_t len)
{
    int w = send(static_cast<Tls *>(p)->fd, buf, len, 0);
    if (w >= 0)
    {
        return w;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
    {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    return errno == ECONNRESET || errno == EPIPE ? MBEDTLS_ERR_NET_CONN_RESET : MBEDTLS_ERR_NET_SEND_FAILED;
}

int BioRecv(void * p, unsigned char * buf, size_t len)
{
    int r = recv(static_cast<Tls *>(p)->fd, buf, len, 0);
    if (r >= 0)
    {
        return r; // 0: the other end closed
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
    {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    return errno == ECONNRESET ? MBEDTLS_ERR_NET_CONN_RESET : MBEDTLS_ERR_NET_RECV_FAILED;
}

int PskCb(void * p, mbedtls_ssl_context * ssl, const unsigned char * id, size_t idLen)
{
    Tls * t = static_cast<Tls *>(p);
    uint8_t psk[kKeyLen];
    int rc = -1;
    if (t->lookup(t->lookupCtx, id, idLen, psk))
    {
        rc = mbedtls_ssl_set_hs_psk(ssl, psk, sizeof(psk));
    }
    else
    {
        t->unknownIdentity = true;
    }
    memset(psk, 0, sizeof(psk));
    return rc;
}

TlsFail Classify(const Tls * t, int rc)
{
    if (t->unknownIdentity)
    {
        return TlsFail::kUnknownSecret;
    }
    switch (rc)
    {
    case MBEDTLS_ERR_SSL_CONN_EOF:
    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
    case MBEDTLS_ERR_NET_CONN_RESET:
    case MBEDTLS_ERR_NET_RECV_FAILED:
    case MBEDTLS_ERR_NET_SEND_FAILED:
        return TlsFail::kClosed;
    case MBEDTLS_ERR_SSL_NO_APPLICATION_PROTOCOL:
        return TlsFail::kProtocol;
    default:
        return TlsFail::kOther;
    }
}

void Free(Tls * t)
{
    mbedtls_ssl_free(&t->ssl);
    mbedtls_ssl_config_free(&t->conf);
    delete t;
}

} // namespace

Tls * TlsAccept(int fd, TlsPskLookup lookup, void * ctx, uint32_t timeoutMs, TlsFail & why, char * detail, size_t detailCap)
{
    why     = TlsFail::kOther;
    Tls * t = new (std::nothrow) Tls;
    if (t == nullptr)
    {
        return nullptr;
    }
    t->fd        = fd;
    t->lookup    = lookup;
    t->lookupCtx = ctx;
    mbedtls_ssl_config_init(&t->conf);
    mbedtls_ssl_init(&t->ssl);
    int rc = mbedtls_ssl_config_defaults(&t->conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc == 0)
    {
        // TLS 1.2 only; no session tickets or cache (none configured), no renegotiation
        mbedtls_ssl_conf_min_tls_version(&t->conf, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(&t->conf, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_ciphersuites(&t->conf, kSuites);
        mbedtls_ssl_conf_groups(&t->conf, kGroups);
        mbedtls_ssl_conf_psk_cb(&t->conf, PskCb, t);
        mbedtls_ssl_conf_encrypt_then_mac(&t->conf, MBEDTLS_SSL_ETM_ENABLED);
        mbedtls_ssl_conf_extended_master_secret(&t->conf, MBEDTLS_SSL_EXTENDED_MS_ENABLED);
#if defined(MBEDTLS_SSL_RENEGOTIATION)
        mbedtls_ssl_conf_renegotiation(&t->conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif
        rc = mbedtls_ssl_conf_alpn_protocols(&t->conf, kAlpns);
    }
    if (rc == 0)
    {
        rc = mbedtls_ssl_setup(&t->ssl, &t->conf);
    }
    if (rc != 0)
    {
        if (detail != nullptr && detailCap > 0)
        {
            snprintf(detail, detailCap, "setup -0x%04x", static_cast<unsigned>(-rc));
        }
        Free(t);
        return nullptr;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    mbedtls_ssl_set_bio(&t->ssl, t, BioSend, BioRecv, nullptr);

    const auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    while ((rc = mbedtls_ssl_handshake(&t->ssl)) != 0)
    {
        if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            why = Classify(t, rc);
            break;
        }
        int left = MsLeft(deadline);
        if (left == 0 || !Wait(fd, rc == MBEDTLS_ERR_SSL_WANT_WRITE, left))
        {
            why = TlsFail::kTimeout;
            break;
        }
    }
    if (rc == 0)
    {
        // The stream's profile: our ALPN, encrypt-then-MAC (CBC), 4 KB records
        // (with MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH the buffers shrink to them).
        // The client's extended master secret is checked on its side.
        const char * alpn                 = mbedtls_ssl_get_alpn_protocol(&t->ssl);
        const mbedtls_ssl_session * sess  = t->ssl.MBEDTLS_PRIVATE(session);
        if (alpn == nullptr || strcmp(alpn, kAlpn) != 0 || sess == nullptr ||
            sess->MBEDTLS_PRIVATE(encrypt_then_mac) != MBEDTLS_SSL_ETM_ENABLED ||
            sess->MBEDTLS_PRIVATE(mfl_code) != MBEDTLS_SSL_MAX_FRAG_LEN_4096)
        {
            why = TlsFail::kProtocol;
            rc  = MBEDTLS_ERR_SSL_NO_APPLICATION_PROTOCOL;
        }
    }
    if (rc != 0)
    {
        if (detail != nullptr && detailCap > 0)
        {
            snprintf(detail, detailCap, "-0x%04x", static_cast<unsigned>(-rc));
        }
        Free(t);
        return nullptr;
    }
    why          = TlsFail::kNone;
    t->lookup    = nullptr;
    t->lookupCtx = nullptr;
    return t;
}

Tls * TlsConnect(int, const uint8_t[kKeyLen], const char *, uint32_t, TlsFail & why, char *, size_t)
{
    why = TlsFail::kOther; // the gateway is only ever the server
    return nullptr;
}

int TlsRead(Tls * t, uint8_t * buf, size_t cap)
{
    std::lock_guard<std::mutex> l(t->io);
    int n = mbedtls_ssl_read(&t->ssl, buf, cap);
    if (n > 0)
    {
        return n;
    }
    switch (n)
    {
    case 0:
    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
    case MBEDTLS_ERR_SSL_CONN_EOF:
        return 0;
    case MBEDTLS_ERR_SSL_WANT_READ:
    case MBEDTLS_ERR_SSL_WANT_WRITE:
        return kTlsAgain;
    default:
        return kTlsError;
    }
}

bool TlsPending(Tls * t)
{
    std::lock_guard<std::mutex> l(t->io);
    return mbedtls_ssl_get_bytes_avail(&t->ssl) > 0;
}

bool TlsWrite(Tls * t, const uint8_t * buf, size_t len, uint32_t timeoutMs)
{
    std::lock_guard<std::mutex> w(t->wr);
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    while (len > 0)
    {
        int n;
        {
            std::lock_guard<std::mutex> l(t->io);
            n = mbedtls_ssl_write(&t->ssl, buf, len);
        }
        if (n > 0)
        {
            buf += n;
            len -= static_cast<size_t>(n);
            continue;
        }
        if (n != MBEDTLS_ERR_SSL_WANT_WRITE && n != MBEDTLS_ERR_SSL_WANT_READ)
        {
            return false;
        }
        int left = MsLeft(deadline);
        if (left == 0 || !Wait(t->fd, n == MBEDTLS_ERR_SSL_WANT_WRITE, left))
        {
            return false;
        }
    }
    return true;
}

bool TlsExportConnKey(Tls * t, uint8_t out[kKeyLen])
{
    std::lock_guard<std::mutex> l(t->io);
    return mbedtls_ssl_export_keying_material(&t->ssl, out, kKeyLen, kExportLabel, sizeof(kExportLabel) - 1, nullptr, 0, 0) == 0;
}

void TlsFree(Tls * t)
{
    if (t != nullptr)
    {
        Free(t);
    }
}

} // namespace mgw
