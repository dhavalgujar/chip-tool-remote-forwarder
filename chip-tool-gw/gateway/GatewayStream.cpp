// SPDX-License-Identifier: Apache-2.0

#include "GatewayStream.h"

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <ctype.h>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <thread>

#include <json/json.h>
#include <lib/support/logging/CHIPLogging.h>

#include "GatewayDial.h"
#include "GatewaySecretFile.h"
#include "mgw_keys.h"
#include "mgw_proto.h"
#include "mgw_tls.h"

namespace GatewayClient {

namespace {

using Clock = std::chrono::steady_clock;

constexpr int kDialTimeoutMs      = 15000;
constexpr int kHandshakeTimeoutMs = 20000;
constexpr int kWriteTimeoutMs     = 15000; // a frame not written by then: the stream is dropped
constexpr int kOpenTimeoutMs      = 15000;
constexpr int kPingEveryMs        = 25000;
constexpr int kDeadAfterMs        = 60000; // no frame for this long: the stream is gone
constexpr unsigned kCallTimeoutS  = 330;   // a call without a timeout of its own

std::string Env(const char * name)
{
    const char * v = getenv(name);
    return v ? v : "";
}

void Wipe(std::string & s)
{
    std::fill(s.begin(), s.end(), '\0');
}

// matter.connect's payload, as saved: {"endpoint": "host:port", "secret": "<hex>", ...}.
bool ReadConnectFile(const std::string & path, std::string & endpoint, uint8_t * secret, size_t cap, size_t & len,
                     std::string & why)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
    {
        why = "can't read MATTER_GW_CONNECT_FILE (" + path + ")";
        return false;
    }
    std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    Json::Value v;
    std::string err;
    std::unique_ptr<Json::CharReader> reader(Json::CharReaderBuilder().newCharReader());
    bool parsed = text.size() <= 16384 && reader->parse(text.data(), text.data() + text.size(), &v, &err);
    Wipe(text);
    if (!parsed || !v.isObject() || !v.isMember("endpoint") || !v["endpoint"].isString() || !v.isMember("secret") ||
        !v["secret"].isString())
    {
        why = "MATTER_GW_CONNECT_FILE must be matter.connect's payload: a JSON object with endpoint and secret";
        return false;
    }
    endpoint       = v["endpoint"].asString();
    std::string hx = v["secret"].asString();
    v              = Json::Value();
    bool hex       = !hx.empty() && std::all_of(hx.begin(), hx.end(), [](char c) { return isxdigit(c) != 0; });
    len            = hex ? ParseSecret(reinterpret_cast<const uint8_t *>(hx.data()), hx.size(), secret, cap) : 0;
    Wipe(hx);
    if (len < mgw::kMinSecretLen)
    {
        why = "the secret in MATTER_GW_CONNECT_FILE must be 32-128 hex digits";
        return false;
    }
    return true;
}

} // namespace

struct GatewayStream::Impl
{
    // configuration
    std::once_flag configOnce;
    bool configured = false;
    bool viaProxy   = false;
    std::string host;
    uint16_t port = 0;
    uint8_t secret[mgw::kMaxSecretLen];
    size_t secretLen = 0;

    // connection: the socket and its TLS session, alive while anyone uses it
    struct Conn
    {
        int fd         = -1;
        mgw::Tls * tls = nullptr;
        ~Conn()
        {
            mgw::TlsFree(tls);
            close(fd);
        }
    };
    std::mutex mu; // cur, connKey, pending, handlers, lastError
    std::mutex dialMu;
    std::shared_ptr<Conn> cur;
    uint32_t counter = 0;
    std::atomic<uint32_t> epoch{ 0 };
    uint8_t connKey[mgw::kKeyLen];
    uint16_t nextReq = 0;

    // A request waiting for its answer (open, call).
    struct Pending
    {
        bool done     = false;
        bool answered = false; // done without an answer: the stream dropped
        bool ok       = false;
        uint16_t v    = 0; // open: gw lsid or error code
        std::string json;
    };
    using PendingMap = std::map<uint16_t, std::shared_ptr<Pending>>;
    PendingMap opens, calls;
    std::condition_variable cv;

    SignHandler sign;
    EventHandler event;
    MatterHandler matter;
    std::string lastError;
    Failure lastFailure = Failure::kNone;

    void Configure();
    void SetError(const std::string & e, Failure kind = Failure::kOther);
    mgw::Tls * Handshake(int c);
    bool EnsureConnected();
    bool Send(uint8_t type, const uint8_t * body, size_t len);
    void Drop(const Conn * which);
    void Reader(std::shared_ptr<Conn> c);
    void Dispatch(const Conn * c, uint8_t type, const uint8_t * body, size_t len);
    uint16_t NewReq();
    Result Exchange(PendingMap & table, const std::function<bool(uint16_t req, std::vector<uint8_t> & body)> & encode,
                    std::chrono::milliseconds timeout, const std::string & what, const std::function<void()> & registered,
                    std::shared_ptr<Pending> & answer);
};

GatewayStream & GatewayStream::Instance()
{
    static GatewayStream s;
    return s;
}

GatewayStream::Impl & GatewayStream::I()
{
    static Impl impl;
    return impl;
}

void GatewayStream::Impl::SetError(const std::string & e, Failure kind)
{
    {
        std::lock_guard<std::mutex> l(mu);
        lastError   = e;
        lastFailure = kind;
    }
    ChipLogError(chipTool, "Gateway: %s", e.c_str());
}

void GatewayStream::Impl::Configure()
{
    std::string target  = Env("MATTER_GW");
    std::string connect = Env("MATTER_GW_CONNECT_FILE");
    if (connect.empty())
    {
        if (!target.empty())
            SetError("MATTER_GW needs MATTER_GW_CONNECT_FILE (matter.connect's payload)");
        return;
    }
    if (target == "proxy")
    {
        viaProxy = true;
        target.clear();
    }
    else if (target.rfind("proxy:", 0) == 0)
    {
        viaProxy = true;
        target   = target.substr(6);
    }
    std::string endpoint, why;
    if (!ReadConnectFile(connect, endpoint, secret, sizeof(secret), secretLen, why))
    {
        SetError(why);
        return;
    }
    if (target.empty())
        target = endpoint;
    if (!SplitHostPort(target, host, port, 0))
    {
        SetError("the gateway's endpoint must be host:port (MATTER_GW_CONNECT_FILE's, or MATTER_GW)");
        return;
    }
    configured = true;
}

// TLS 1.2 (ECDHE-PSK) with the PSK from the secret (mgw_proto.h); sets connKey.
mgw::Tls * GatewayStream::Impl::Handshake(int c)
{
    uint8_t psk[mgw::kKeyLen];
    char identity[mgw::kIdentityLen];
    if (!mgw::TlsPsk(secret, secretLen, psk) || !mgw::TlsIdentity(secret, secretLen, identity))
    {
        SetError("can't derive the TLS key");
        return nullptr;
    }
    mgw::TlsFail why;
    char detail[96] = "";
    mgw::Tls * tls  = mgw::TlsConnect(c, psk, identity, kHandshakeTimeoutMs, why, detail, sizeof(detail));
    memset(psk, 0, sizeof(psk));
    if (tls == nullptr)
    {
        switch (why)
        {
        case mgw::TlsFail::kUnknownSecret:
            SetError("the gateway does not know this secret", Failure::kUnknownSecret);
            break;
        case mgw::TlsFail::kProtocol:
            SetError("the gateway speaks another protocol version", Failure::kOldProtocol);
            break;
        case mgw::TlsFail::kClosed:
            SetError("the gateway closed the connection during the TLS handshake (busy, or firmware without TLS)",
                     Failure::kOldProtocol);
            break;
        case mgw::TlsFail::kNotTls:
            SetError("the gateway doesn't speak TLS (firmware without TLS)", Failure::kOldProtocol);
            break;
        case mgw::TlsFail::kTimeout:
            SetError("TLS handshake: no answer from the gateway", Failure::kUnreachable);
            break;
        default:
            SetError(std::string("TLS handshake failed: ") + detail);
            break;
        }
        return nullptr;
    }
    uint8_t key[mgw::kKeyLen];
    if (!mgw::TlsExportConnKey(tls, key))
    {
        mgw::TlsFree(tls);
        SetError("TLS: no exported key");
        return nullptr;
    }
    std::lock_guard<std::mutex> l(mu);
    memcpy(connKey, key, sizeof(key));
    memset(key, 0, sizeof(key));
    return tls;
}

bool GatewayStream::Impl::EnsureConnected()
{
    std::lock_guard<std::mutex> dial(dialMu);
    {
        std::lock_guard<std::mutex> l(mu);
        if (cur)
            return true;
    }
    std::string target = HostPort(host, port);
    int c;
    if (viaProxy)
    {
        std::string why;
        Failure kind;
        c = DialProxy(target, kDialTimeoutMs, why, kind);
        if (c < 0)
            SetError(why, kind);
    }
    else
    {
        c = DialTcp(host, port, kDialTimeoutMs);
        if (c < 0)
            SetError("can't connect to the gateway at " + target, Failure::kUnreachable);
    }
    if (c < 0)
        return false;
    int one = 1;
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(c, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    mgw::Tls * tls = Handshake(c);
    if (tls == nullptr)
    {
        close(c);
        return false;
    }
    auto conn = std::make_shared<Conn>();
    conn->fd  = c;
    conn->tls = tls;
    {
        std::lock_guard<std::mutex> l(mu);
        cur = conn;
        epoch.store(++counter);
        lastError.clear();
        lastFailure = Failure::kNone;
    }
    std::thread([this, conn] { Reader(conn); }).detach();
    ChipLogProgress(chipTool, "Gateway: connected to %s%s (TLS)", target.c_str(), viaProxy ? " through the CONNECT proxy" : "");
    return true;
}

bool GatewayStream::Impl::Send(uint8_t type, const uint8_t * body, size_t len)
{
    std::shared_ptr<Conn> c;
    {
        std::lock_guard<std::mutex> l(mu);
        c = cur;
    }
    if (!c)
        return false;
    // One write per frame: writers on other threads can't interleave.
    std::vector<uint8_t> frame(mgw::kFrameHeaderLen + len);
    bool ok = mgw::FrameHeader(frame.data(), type, len);
    if (ok && len > 0)
        memcpy(frame.data() + mgw::kFrameHeaderLen, body, len);
    ok = ok && mgw::TlsWrite(c->tls, frame.data(), frame.size(), kWriteTimeoutMs);
    if (!ok)
        Drop(c.get());
    return ok;
}

// The stream `which` is gone: fail what waits on it. The socket closes when
// the last user (the reader thread, a writer) lets go of it.
void GatewayStream::Impl::Drop(const Conn * which)
{
    std::lock_guard<std::mutex> l(mu);
    if (!cur || cur.get() != which)
        return;
    shutdown(cur->fd, SHUT_RDWR);
    cur.reset();
    epoch.store(0);
    memset(connKey, 0, sizeof(connKey));
    for (auto & kv : opens)
        kv.second->done = true;
    for (auto & kv : calls)
        kv.second->done = true;
    opens.clear();
    calls.clear();
    cv.notify_all();
}

void GatewayStream::Impl::Reader(std::shared_ptr<Conn> c)
{
    auto rd        = std::make_unique<mgw::FrameReader>();
    auto lastRx    = Clock::now();
    auto nextPing  = lastRx + std::chrono::milliseconds(kPingEveryMs);
    uint8_t buf[4096];
    for (;;)
    {
        auto now = Clock::now();
        if (now - lastRx > std::chrono::milliseconds(kDeadAfterMs))
        {
            ChipLogError(chipTool, "Gateway: no answer for %d s; dropping the stream", kDeadAfterMs / 1000);
            break;
        }
        if (now >= nextPing)
        {
            mgw::PingMsg m;
            m.token = static_cast<uint32_t>(time(nullptr));
            uint8_t ping[mgw::PingMsg::kLen];
            m.Encode(ping);
            if (!Send(mgw::kFrameControl, ping, sizeof(ping)))
                break;
            nextPing = now + std::chrono::milliseconds(kPingEveryMs);
        }
        // Records TLS already decrypted don't make the socket readable.
        if (!mgw::TlsPending(c->tls))
        {
            pollfd p     = { c->fd, POLLIN, 0 };
            auto until   = std::min(nextPing, lastRx + std::chrono::milliseconds(kDeadAfterMs));
            auto waitMs  = std::chrono::duration_cast<std::chrono::milliseconds>(until - Clock::now()).count();
            int pr       = poll(&p, 1, waitMs > 0 ? static_cast<int>(waitMs) : 1);
            if (pr < 0 && errno != EINTR)
                break;
            if (pr <= 0)
                continue;
        }
        int n = mgw::TlsRead(c->tls, buf, sizeof(buf));
        if (n == mgw::kTlsAgain)
            continue;
        if (n <= 0)
            break;
        lastRx      = Clock::now();
        size_t used = 0;
        bool bad    = false;
        while (used < static_cast<size_t>(n))
        {
            used += rd->Feed(buf + used, static_cast<size_t>(n) - used);
            if (rd->Bad())
            {
                bad = true;
                break;
            }
            if (rd->Ready())
            {
                Dispatch(c.get(), rd->Type(), rd->Body(), rd->BodyLen());
                rd->Consume();
            }
        }
        if (bad)
        {
            ChipLogError(chipTool, "Gateway: bad frame from the gateway");
            break;
        }
    }
    Drop(c.get());
}

void GatewayStream::Impl::Dispatch(const Conn * c, uint8_t type, const uint8_t * b, size_t n)
{
    if (type == mgw::kFrameMatter)
    {
        MatterHandler h;
        {
            std::lock_guard<std::mutex> l(mu);
            h = matter;
        }
        if (h)
            h(b, n);
        return;
    }
    if (type != mgw::kFrameControl || n < 1)
        return;
    switch (b[0])
    {
    case mgw::kOpOpenOk:
    case mgw::kOpOpenErr: {
        mgw::OpenReplyMsg m;
        if (!m.Decode(b, n))
            return;
        std::lock_guard<std::mutex> l(mu);
        auto it = opens.find(m.req);
        if (it != opens.end())
        {
            it->second->answered = true;
            it->second->ok       = m.ok;
            it->second->v        = m.value;
            it->second->done     = true;
            opens.erase(it);
            cv.notify_all();
        }
        return;
    }
    case mgw::kOpResult: {
        mgw::ResultMsg m;
        if (!m.Decode(b, n))
            return;
        std::lock_guard<std::mutex> l(mu);
        auto it = calls.find(m.req);
        if (it != calls.end())
        {
            it->second->answered = true;
            it->second->ok       = true;
            it->second->json.assign(m.json, m.jsonLen);
            it->second->done = true;
            calls.erase(it);
            cv.notify_all();
        }
        return;
    }
    case mgw::kOpSign: {
        std::vector<uint8_t> req(b + 1, b + n);
        SignHandler h;
        {
            std::lock_guard<std::mutex> l(mu);
            h = sign;
        }
        // Signing waits for the CHIP thread: never on the reader.
        std::thread([this, req, h] {
            std::vector<uint8_t> out;
            if (h)
                out = h(req.data(), req.size());
            std::vector<uint8_t> body{ mgw::kOpSigned };
            if (out.empty())
            {
                if (!h)
                    ChipLogError(chipTool, "Gateway: a signing request, but no signer here (use gateway call with the fabric's storage)");
                // signed: req, status (mgw_proto.h)
                uint8_t r[4];
                mgw::Put16(r, req.size() >= 2 ? mgw::Get16(req.data()) : 0);
                mgw::Put16(r + 2, mgw::kErrSigner);
                body.insert(body.end(), r, r + 4);
            }
            else
            {
                body.insert(body.end(), out.begin(), out.end());
            }
            Send(mgw::kFrameControl, body.data(), body.size());
        }).detach();
        return;
    }
    case mgw::kOpEvent: {
        mgw::EventMsg m;
        if (!m.Decode(b, n))
            return;
        EventHandler h;
        {
            std::lock_guard<std::mutex> l(mu);
            h = event;
        }
        if (h)
            h(m.kind, m.node);
        return;
    }
    case mgw::kOpError: {
        mgw::ErrorMsg m;
        if (m.Decode(b, n))
        {
            const uint16_t code = m.code;
            ChipLogError(chipTool, "Gateway: the gateway closed the stream: %s", mgw::ErrName(code));
            SetError(code == mgw::kErrBusy ? std::string("the gateway is busy: all its connections are in use")
                                           : std::string("the gateway closed the stream: ") + mgw::ErrName(code));
        }
        shutdown(c->fd, SHUT_RDWR); // the reader ends and drops it
        return;
    }
    default: // pong and anything newer
        return;
    }
}

uint16_t GatewayStream::Impl::NewReq()
{
    return ++nextReq;
}

// One request and its answer: registers a pending entry in `table` under a new
// request ID (running `registered`, if given, under the same lock), sends the
// control message encode() builds for that ID and waits up to `timeout`; what
// prefixes its errors ("" for a call: its caller names it). kOk:
// `answer` holds the gateway's answer. Any other result has recorded why
// (LastError, LastFailure), so the hint chip-tool-gw prints is about this
// request.
GatewayStream::Result GatewayStream::Impl::Exchange(PendingMap & table,
                                                    const std::function<bool(uint16_t req, std::vector<uint8_t> & body)> & encode,
                                                    std::chrono::milliseconds timeout, const std::string & what,
                                                    const std::function<void()> & registered, std::shared_ptr<Pending> & answer)
{
    if (!EnsureConnected())
        return Result::kNoStream; // it said why
    auto p = std::make_shared<Pending>();
    uint16_t req;
    {
        std::lock_guard<std::mutex> l(mu);
        req        = NewReq();
        table[req] = p;
        if (registered)
            registered();
    }
    std::vector<uint8_t> body;
    const bool encoded = encode(req, body) && body.size() <= mgw::kMaxFrameBody;
    if (!encoded || !Send(mgw::kFrameControl, body.data(), body.size()))
    {
        {
            std::lock_guard<std::mutex> l(mu);
            table.erase(req); // Drop() clears only the current stream's
        }
        SetError(what + (encoded ? "the stream dropped" : "the request is too large"));
        return encoded ? Result::kNoStream : Result::kRefused;
    }
    std::unique_lock<std::mutex> l(mu);
    const bool done = cv.wait_for(l, timeout, [&] { return p->done; });
    if (!done)
        table.erase(req);
    l.unlock();
    if (!done)
    {
        // Only this request fails (the gateway may be busy, e.g. commissioning);
        // the reader's liveness check ends a dead stream.
        SetError(what + "no answer from the gateway in time");
        return Result::kNoStream;
    }
    if (!p->answered)
    {
        SetError(what + "the stream dropped");
        return Result::kNoStream;
    }
    answer = p;
    return Result::kOk;
}

bool GatewayStream::Configured()
{
    Impl & i = I();
    std::call_once(i.configOnce, [&i] { i.Configure(); });
    return i.configured;
}

uint32_t GatewayStream::Epoch()
{
    return I().epoch.load();
}

bool GatewayStream::SendMatter(const uint8_t * msg, size_t len)
{
    return I().Send(mgw::kFrameMatter, msg, len);
}

void GatewayStream::SetMatterHandler(MatterHandler handler)
{
    Impl & i = I();
    std::lock_guard<std::mutex> l(i.mu);
    i.matter = std::move(handler);
}

GatewayStream::Result GatewayStream::Open(uint64_t node, uint16_t cloudLsid, uint64_t cloudNode, uint16_t & gwLsid,
                                          uint8_t secretOut[32], uint16_t & code, uint32_t & epochOut)
{
    Impl & i = I();
    if (!Configured())
        return Result::kNotConfigured;
    uint8_t key[mgw::kKeyLen];
    auto encode = [&](uint16_t req, std::vector<uint8_t> & body) {
        mgw::OpenMsg m;
        m.req       = req;
        m.node      = node;
        m.cloudLsid = cloudLsid;
        m.cloudNode = cloudNode;
        body.resize(mgw::OpenMsg::kLen);
        m.Encode(body.data());
        return true;
    };
    // The key and epoch of the connection the request goes out on.
    auto keep = [&] {
        memcpy(key, i.connKey, sizeof(key));
        epochOut = i.epoch.load();
    };
    std::shared_ptr<Impl::Pending> answer;
    Result r = i.Exchange(i.opens, encode, std::chrono::milliseconds(kOpenTimeoutMs), "session request: ", keep, answer);
    if (r == Result::kOk && !answer->ok)
    {
        code = answer->v;
        r    = Result::kRefused;
    }
    else if (r == Result::kOk)
    {
        gwLsid = answer->v;
        if (!mgw::SessionSecret(key, node, cloudLsid, gwLsid, secretOut))
        {
            i.SetError("session request: can't derive the session key");
            r = Result::kNoStream;
        }
    }
    memset(key, 0, sizeof(key));
    return r;
}

void GatewayStream::Close(uint16_t cloudLsid, uint16_t gwLsid)
{
    mgw::CloseMsg m;
    m.cloudLsid = cloudLsid;
    m.gwLsid    = gwLsid;
    uint8_t body[mgw::CloseMsg::kLen];
    m.Encode(body);
    I().Send(mgw::kFrameControl, body, sizeof(body));
}

GatewayStream::Result GatewayStream::Call(const std::string & name, const std::string & params, unsigned timeoutS,
                                          std::string & out)
{
    Impl & i = I();
    if (!Configured())
        return Result::kNotConfigured;
    if (name.empty() || name.size() > mgw::kMaxCallName)
    {
        i.SetError("the command name must be 1-" + std::to_string(mgw::kMaxCallName) + " characters");
        return Result::kRefused;
    }
    auto encode = [&](uint16_t req, std::vector<uint8_t> & body) {
        mgw::CallMsg m;
        m.req       = req;
        m.name      = name.data();
        m.nameLen   = name.size();
        m.params    = params.data();
        m.paramsLen = params.size();
        body.resize(m.Len());
        return m.Encode(body.data(), body.size());
    };
    std::shared_ptr<Impl::Pending> answer;
    Result r = i.Exchange(i.calls, encode, std::chrono::seconds(timeoutS ? timeoutS : kCallTimeoutS), "", nullptr, answer);
    if (r == Result::kOk)
        out = answer->json;
    return r;
}

void GatewayStream::SetSignHandler(SignHandler handler)
{
    std::lock_guard<std::mutex> l(I().mu);
    I().sign = std::move(handler);
}

void GatewayStream::SetEventHandler(EventHandler handler)
{
    std::lock_guard<std::mutex> l(I().mu);
    I().event = std::move(handler);
}

std::string GatewayStream::LastError()
{
    std::lock_guard<std::mutex> l(I().mu);
    return I().lastError;
}

GatewayStream::Failure GatewayStream::LastFailure()
{
    std::lock_guard<std::mutex> l(I().mu);
    return I().lastFailure;
}

} // namespace GatewayClient
