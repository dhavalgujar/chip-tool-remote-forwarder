// SPDX-License-Identifier: Apache-2.0

// ctf_tls.h on OpenSSL 3 (host: chip-tool-remote's client, forwarder-host's server).
#include "ctf_tls.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include <chrono>
#include <mutex>

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace ctf {

struct Tls
{
    SSL_CTX * ctx = nullptr;
    SSL * ssl     = nullptr;
    int fd        = -1;
    std::mutex io; // SSL_read / SSL_write
    std::mutex wr; // one TlsWrite at a time
    // handshake only
    TlsPskLookup lookup   = nullptr;
    void * lookupCtx      = nullptr;
    const uint8_t * psk   = nullptr;
    const char * identity = nullptr;
    bool unknownIdentity  = false;
};

namespace {

using Clock = std::chrono::steady_clock;

int MsLeft(Clock::time_point deadline)
{
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    return ms < 0 ? 0 : static_cast<int>(ms);
}

const char kSuite[]               = "ECDHE-PSK-AES128-CBC-SHA256";
// kAlpn in ALPN wire form (a length byte, then the name).
struct AlpnWire
{
    unsigned char b[sizeof(kAlpn)];
    AlpnWire()
    {
        b[0] = sizeof(kAlpn) - 1;
        memcpy(b + 1, kAlpn, sizeof(kAlpn) - 1);
    }
};
const AlpnWire kAlpnWire;

unsigned int ClientPsk(SSL * ssl, const char *, char * identity, unsigned int maxIdentity, unsigned char * psk,
                       unsigned int maxPsk)
{
    Tls * t        = static_cast<Tls *>(SSL_get_app_data(ssl));
    const size_t n = strlen(t->identity);
    if (n + 1 > maxIdentity || kKeyLen > maxPsk)
    {
        return 0;
    }
    memcpy(identity, t->identity, n + 1);
    memcpy(psk, t->psk, kKeyLen);
    return kKeyLen;
}

unsigned int ServerPsk(SSL * ssl, const char * identity, unsigned char * psk, unsigned int maxPsk)
{
    Tls * t = static_cast<Tls *>(SSL_get_app_data(ssl));
    uint8_t key[kKeyLen];
    unsigned int n = 0;
    if (identity != nullptr && maxPsk >= kKeyLen &&
        t->lookup(t->lookupCtx, reinterpret_cast<const uint8_t *>(identity), strlen(identity), key))
    {
        memcpy(psk, key, kKeyLen);
        n = kKeyLen;
    }
    else
    {
        t->unknownIdentity = true;
    }
    memset(key, 0, sizeof(key));
    return n; // 0: unknown identity, the handshake fails
}

int SelectAlpn(SSL *, const unsigned char ** out, unsigned char * outLen, const unsigned char * in, unsigned int inLen, void *)
{
    unsigned char * sel = nullptr;
    if (SSL_select_next_proto(&sel, outLen, kAlpnWire.b, sizeof(kAlpnWire.b), in, inLen) != OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_ALERT_FATAL; // no_application_protocol
    }
    *out = sel;
    return SSL_TLSEXT_ERR_OK;
}

// A socket BIO that never raises SIGPIPE.
int BioWrite(BIO * b, const char * d, int n)
{
    BIO_clear_retry_flags(b);
    ssize_t w = send(static_cast<int>(reinterpret_cast<intptr_t>(BIO_get_data(b))), d, static_cast<size_t>(n), MSG_NOSIGNAL);
    if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
    {
        BIO_set_retry_write(b);
    }
    return static_cast<int>(w);
}

int BioRead(BIO * b, char * d, int n)
{
    BIO_clear_retry_flags(b);
    ssize_t r = recv(static_cast<int>(reinterpret_cast<intptr_t>(BIO_get_data(b))), d, static_cast<size_t>(n), 0);
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
    {
        BIO_set_retry_read(b);
    }
    return static_cast<int>(r);
}

long BioCtrl(BIO *, int cmd, long, void *)
{
    return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}

int BioCreate(BIO * b)
{
    BIO_set_init(b, 1);
    return 1;
}

BIO * SocketBio(int fd)
{
    static BIO_METHOD * method = [] {
        BIO_METHOD * m = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "ctf-socket");
        if (m != nullptr)
        {
            BIO_meth_set_write(m, BioWrite);
            BIO_meth_set_read(m, BioRead);
            BIO_meth_set_ctrl(m, BioCtrl);
            BIO_meth_set_create(m, BioCreate);
        }
        return m;
    }();
    BIO * b = method != nullptr ? BIO_new(method) : nullptr;
    if (b != nullptr)
    {
        BIO_set_data(b, reinterpret_cast<void *>(static_cast<intptr_t>(fd)));
    }
    return b;
}

void Detail(unsigned long e, char * detail, size_t cap)
{
    if (detail != nullptr && cap > 0)
    {
        const char * r = e != 0 ? ERR_reason_error_string(e) : nullptr;
        snprintf(detail, cap, "%s", r != nullptr ? r : (errno != 0 ? strerror(errno) : "closed"));
    }
}

// Why the handshake failed, from the error queue (and errno for a socket error).
TlsFail Classify(int sslErr, unsigned long e)
{
    if (e == 0 || ERR_GET_LIB(e) != ERR_LIB_SSL)
    {
        return sslErr == SSL_ERROR_SYSCALL || sslErr == SSL_ERROR_ZERO_RETURN ? TlsFail::kClosed : TlsFail::kOther;
    }
    const int reason = ERR_GET_REASON(e);
    if (reason > SSL_AD_REASON_OFFSET && reason < SSL_AD_REASON_OFFSET + 256) // an alert from the other end
    {
        switch (reason - SSL_AD_REASON_OFFSET)
        {
        case SSL_AD_HANDSHAKE_FAILURE:
        case SSL_AD_DECRYPT_ERROR:
        case SSL_AD_UNKNOWN_PSK_IDENTITY:
            return TlsFail::kUnknownSecret;
        case SSL_AD_NO_APPLICATION_PROTOCOL:
            return TlsFail::kProtocol;
        default:
            return TlsFail::kOther;
        }
    }
    switch (reason)
    {
    case SSL_R_UNEXPECTED_EOF_WHILE_READING:
        return TlsFail::kClosed;
    case SSL_R_WRONG_VERSION_NUMBER:
    case SSL_R_PACKET_LENGTH_TOO_LONG:
    case SSL_R_UNKNOWN_PROTOCOL:
    case SSL_R_HTTP_REQUEST:
    case SSL_R_HTTPS_PROXY_REQUEST:
        return TlsFail::kNotTls;
    case SSL_R_NO_SHARED_CIPHER:
        return TlsFail::kUnknownSecret;
    default:
        return TlsFail::kOther;
    }
}

Tls * Handshake(Tls * t, bool server, uint32_t timeoutMs, TlsFail & why, char * detail, size_t detailCap)
{
    why = TlsFail::kOther;
    int flags = fcntl(t->fd, F_GETFL, 0);
    fcntl(t->fd, F_SETFL, flags | O_NONBLOCK);
    BIO * bio = SocketBio(t->fd);
    if (bio == nullptr)
    {
        TlsFree(t);
        return nullptr;
    }
    SSL_set_bio(t->ssl, bio, bio);
    SSL_set_app_data(t->ssl, t);
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    for (;;)
    {
        ERR_clear_error();
        errno      = 0;
        int rc     = server ? SSL_accept(t->ssl) : SSL_connect(t->ssl);
        if (rc == 1)
        {
            break;
        }
        int err = SSL_get_error(t->ssl, rc);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        {
            pollfd p = { t->fd, static_cast<short>(err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT), 0 };
            int left = MsLeft(deadline);
            if (left == 0 || poll(&p, 1, left) == 0)
            {
                why = TlsFail::kTimeout;
                Detail(0, detail, detailCap);
                TlsFree(t);
                return nullptr;
            }
            continue;
        }
        unsigned long e = ERR_peek_error();
        why             = server && t->unknownIdentity ? TlsFail::kUnknownSecret : Classify(err, e);
        Detail(e, detail, detailCap);
        TlsFree(t);
        return nullptr;
    }
    const unsigned char * alpn = nullptr;
    unsigned int alpnLen       = 0;
    SSL_get0_alpn_selected(t->ssl, &alpn, &alpnLen);
    // the exporter's key is only sound with the extended master secret (RFC 7627).
    // As a server (forwarder-host, for tests) encrypt-then-MAC and the 4 KB record
    // limit aren't required of the client, unlike on the ESP32.
    if (alpnLen != sizeof(kAlpn) - 1 || memcmp(alpn, kAlpn, alpnLen) != 0 || SSL_get_extms_support(t->ssl) != 1)
    {
        why = TlsFail::kProtocol;
        Detail(0, detail, detailCap);
        TlsFree(t);
        return nullptr;
    }
    why          = TlsFail::kNone;
    t->psk       = nullptr;
    t->identity  = nullptr;
    t->lookup    = nullptr;
    return t;
}

Tls * NewTls(int fd, bool server)
{
    Tls * t = new (std::nothrow) Tls;
    if (t == nullptr)
    {
        return nullptr;
    }
    t->fd  = fd;
    t->ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (t->ctx == nullptr || !SSL_CTX_set_min_proto_version(t->ctx, TLS1_2_VERSION) ||
        !SSL_CTX_set_max_proto_version(t->ctx, TLS1_2_VERSION) || !SSL_CTX_set_cipher_list(t->ctx, kSuite) ||
        !SSL_CTX_set1_groups_list(t->ctx, "P-256"))
    {
        TlsFree(t);
        return nullptr;
    }
    // encrypt-then-MAC and the extended master secret are OpenSSL's defaults
    SSL_CTX_set_options(t->ctx, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_mode(t->ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_session_cache_mode(t->ctx, SSL_SESS_CACHE_OFF);
    if (server)
    {
        SSL_CTX_set_psk_server_callback(t->ctx, ServerPsk);
        SSL_CTX_set_alpn_select_cb(t->ctx, SelectAlpn, nullptr);
    }
    else
    {
        SSL_CTX_set_psk_client_callback(t->ctx, ClientPsk);
    }
    t->ssl = SSL_new(t->ctx);
    // 4 KB records (our frames are at most 4099 bytes): the forwarder keeps small buffers
    if (t->ssl == nullptr || (!server && SSL_set_alpn_protos(t->ssl, kAlpnWire.b, sizeof(kAlpnWire.b)) != 0) ||
        (!server && !SSL_set_tlsext_max_fragment_length(t->ssl, TLSEXT_max_fragment_length_4096)))
    {
        TlsFree(t);
        return nullptr;
    }
    return t;
}

} // namespace

Tls * TlsAccept(int fd, TlsPskLookup lookup, void * ctx, uint32_t timeoutMs, TlsFail & why, char * detail, size_t detailCap)
{
    Tls * t = NewTls(fd, true);
    if (t == nullptr)
    {
        why = TlsFail::kOther;
        return nullptr;
    }
    t->lookup    = lookup;
    t->lookupCtx = ctx;
    return Handshake(t, true, timeoutMs, why, detail, detailCap);
}

Tls * TlsConnect(int fd, const uint8_t psk[kKeyLen], const char * identity, uint32_t timeoutMs, TlsFail & why, char * detail,
                 size_t detailCap)
{
    Tls * t = NewTls(fd, false);
    if (t == nullptr)
    {
        why = TlsFail::kOther;
        return nullptr;
    }
    t->psk      = psk;
    t->identity = identity;
    return Handshake(t, false, timeoutMs, why, detail, detailCap);
}

int TlsRead(Tls * t, uint8_t * buf, size_t cap)
{
    std::lock_guard<std::mutex> l(t->io);
    ERR_clear_error();
    errno = 0;
    int n = SSL_read(t->ssl, buf, static_cast<int>(cap));
    if (n > 0)
    {
        return n;
    }
    switch (SSL_get_error(t->ssl, n))
    {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        return kTlsAgain;
    case SSL_ERROR_ZERO_RETURN:
        return 0;
    case SSL_ERROR_SYSCALL:
        return errno == 0 ? 0 : kTlsError;
    default:
        // OpenSSL 3 reports a plain TCP close as an error ("unexpected eof")
        return ERR_GET_REASON(ERR_peek_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING ? 0 : kTlsError;
    }
}

bool TlsPending(Tls * t)
{
    std::lock_guard<std::mutex> l(t->io);
    return SSL_pending(t->ssl) > 0;
}

bool TlsWrite(Tls * t, const uint8_t * buf, size_t len, uint32_t timeoutMs)
{
    std::lock_guard<std::mutex> w(t->wr);
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    while (len > 0)
    {
        int n, err;
        {
            std::lock_guard<std::mutex> l(t->io);
            ERR_clear_error();
            n   = SSL_write(t->ssl, buf, static_cast<int>(len));
            err = n > 0 ? SSL_ERROR_NONE : SSL_get_error(t->ssl, n);
        }
        if (n > 0)
        {
            buf += n;
            len -= static_cast<size_t>(n);
            continue;
        }
        if (err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_READ)
        {
            return false;
        }
        pollfd p = { t->fd, static_cast<short>(err == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN), 0 };
        int left = MsLeft(deadline);
        if (left == 0 || poll(&p, 1, left) == 0)
        {
            return false;
        }
    }
    return true;
}

bool TlsExportConnKey(Tls * t, uint8_t out[kKeyLen])
{
    std::lock_guard<std::mutex> l(t->io);
    return SSL_export_keying_material(t->ssl, out, kKeyLen, kExportLabel, sizeof(kExportLabel) - 1, nullptr, 0, 0) == 1;
}

void TlsFree(Tls * t)
{
    if (t == nullptr)
    {
        return;
    }
    SSL_free(t->ssl); // frees the BIO
    SSL_CTX_free(t->ctx);
    delete t;
}

} // namespace ctf
