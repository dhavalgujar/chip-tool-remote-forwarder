// SPDX-License-Identifier: Apache-2.0

#include "ForwarderStream.h"

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
#include <map>
#include <memory>
#include <mutex>
#include <thread>

#include <lib/support/logging/CHIPLogging.h>

#include "ForwarderDial.h"
#include "ForwarderConnectFile.h"
#include "ctf_keys.h"
#include "ctf_proto.h"
#include "ctf_tls.h"

namespace ForwarderClient {

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

} // namespace

struct ForwarderStream::Impl
{
    // configuration
    std::once_flag configOnce;
    bool configured = false;
    bool viaProxy   = false;
    std::string host;
    uint16_t port = 0;
    uint8_t secret[ctf::kMaxSecretLen];
    size_t secretLen = 0;

    // connection: the socket and its TLS session, alive while anyone uses it
    struct Conn
    {
        int fd         = -1;
        ctf::Tls * tls = nullptr;
        ~Conn()
        {
            ctf::TlsFree(tls);
            close(fd);
        }
    };
    std::mutex mu; // cur, connKey, pending, handlers, lastError
    std::mutex dialMu;
    std::shared_ptr<Conn> cur;
    uint32_t counter = 0;
    std::atomic<uint32_t> epoch{ 0 };
    uint8_t connKey[ctf::kKeyLen];
    uint16_t nextReq = 0;

    // A request waiting for its answer (open, call).
    struct Pending
    {
        bool done     = false;
        bool answered = false; // done without an answer: the stream dropped
        bool ok       = false;
        uint16_t v    = 0; // open: fwd lsid or error code
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
    ctf::Tls * Handshake(int c);
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

ForwarderStream & ForwarderStream::Instance()
{
    static ForwarderStream s;
    return s;
}

ForwarderStream::Impl & ForwarderStream::I()
{
    static Impl impl;
    return impl;
}

void ForwarderStream::Impl::SetError(const std::string & e, Failure kind)
{
    {
        std::lock_guard<std::mutex> l(mu);
        lastError   = e;
        lastFailure = kind;
    }
    ChipLogError(chipTool, "Forwarder: %s", e.c_str());
}

void ForwarderStream::Impl::Configure()
{
    std::string target  = Env("CHIP_TOOL_REMOTE_TARGET");
    std::string connect = Env("CHIP_TOOL_REMOTE_CONNECT_FILE");
    if (connect.empty())
    {
        if (!target.empty())
            SetError("CHIP_TOOL_REMOTE_TARGET needs CHIP_TOOL_REMOTE_CONNECT_FILE (matter.connect's payload)");
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
    if (!ReadConnectFile(connect, "CHIP_TOOL_REMOTE_CONNECT_FILE", endpoint, secret, sizeof(secret), secretLen, why))
    {
        SetError(why);
        return;
    }
    if (target.empty())
        target = endpoint;
    if (!SplitHostPort(target, host, port, 0))
    {
        SetError("the forwarder's endpoint must be host:port (CHIP_TOOL_REMOTE_CONNECT_FILE's, or CHIP_TOOL_REMOTE_TARGET)");
        return;
    }
    configured = true;
}

// TLS 1.2 (ECDHE-PSK) with the PSK from the secret (ctf_proto.h); sets connKey.
ctf::Tls * ForwarderStream::Impl::Handshake(int c)
{
    uint8_t psk[ctf::kKeyLen];
    char identity[ctf::kIdentityLen];
    if (!ctf::TlsPsk(secret, secretLen, psk) || !ctf::TlsIdentity(secret, secretLen, identity))
    {
        SetError("can't derive the TLS key");
        return nullptr;
    }
    ctf::TlsFail why;
    char detail[96] = "";
    ctf::Tls * tls  = ctf::TlsConnect(c, psk, identity, kHandshakeTimeoutMs, why, detail, sizeof(detail));
    memset(psk, 0, sizeof(psk));
    if (tls == nullptr)
    {
        switch (why)
        {
        case ctf::TlsFail::kUnknownSecret:
            SetError("the forwarder does not know this secret", Failure::kUnknownSecret);
            break;
        case ctf::TlsFail::kProtocol:
            SetError("the forwarder speaks another protocol version", Failure::kOldProtocol);
            break;
        case ctf::TlsFail::kClosed:
            SetError("the forwarder closed the connection during the TLS handshake (busy, or firmware without TLS)",
                     Failure::kOldProtocol);
            break;
        case ctf::TlsFail::kNotTls:
            SetError("the forwarder doesn't speak TLS (firmware without TLS)", Failure::kOldProtocol);
            break;
        case ctf::TlsFail::kTimeout:
            SetError("TLS handshake: no answer from the forwarder", Failure::kUnreachable);
            break;
        default:
            SetError(std::string("TLS handshake failed: ") + detail);
            break;
        }
        return nullptr;
    }
    uint8_t key[ctf::kKeyLen];
    if (!ctf::TlsExportConnKey(tls, key))
    {
        ctf::TlsFree(tls);
        SetError("TLS: no exported key");
        return nullptr;
    }
    std::lock_guard<std::mutex> l(mu);
    memcpy(connKey, key, sizeof(key));
    memset(key, 0, sizeof(key));
    return tls;
}

bool ForwarderStream::Impl::EnsureConnected()
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
            SetError("can't connect to the forwarder at " + target, Failure::kUnreachable);
    }
    if (c < 0)
        return false;
    int one = 1;
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(c, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    ctf::Tls * tls = Handshake(c);
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
    ChipLogProgress(chipTool, "Forwarder: connected to %s%s (TLS)", target.c_str(), viaProxy ? " through the CONNECT proxy" : "");
    return true;
}

bool ForwarderStream::Impl::Send(uint8_t type, const uint8_t * body, size_t len)
{
    std::shared_ptr<Conn> c;
    {
        std::lock_guard<std::mutex> l(mu);
        c = cur;
    }
    if (!c)
        return false;
    // One write per frame: writers on other threads can't interleave.
    std::vector<uint8_t> frame(ctf::kFrameHeaderLen + len);
    bool ok = ctf::FrameHeader(frame.data(), type, len);
    if (ok && len > 0)
        memcpy(frame.data() + ctf::kFrameHeaderLen, body, len);
    ok = ok && ctf::TlsWrite(c->tls, frame.data(), frame.size(), kWriteTimeoutMs);
    if (!ok)
        Drop(c.get());
    return ok;
}

// The stream `which` is gone: fail what waits on it. The socket closes when
// the last user (the reader thread, a writer) lets go of it.
void ForwarderStream::Impl::Drop(const Conn * which)
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

void ForwarderStream::Impl::Reader(std::shared_ptr<Conn> c)
{
    auto rd        = std::make_unique<ctf::FrameReader>();
    auto lastRx    = Clock::now();
    auto nextPing  = lastRx + std::chrono::milliseconds(kPingEveryMs);
    uint8_t buf[4096];
    for (;;)
    {
        auto now = Clock::now();
        if (now - lastRx > std::chrono::milliseconds(kDeadAfterMs))
        {
            ChipLogError(chipTool, "Forwarder: no answer for %d s; dropping the stream", kDeadAfterMs / 1000);
            break;
        }
        if (now >= nextPing)
        {
            ctf::PingMsg m;
            m.token = static_cast<uint32_t>(time(nullptr));
            uint8_t ping[ctf::PingMsg::kLen];
            m.Encode(ping);
            if (!Send(ctf::kFrameControl, ping, sizeof(ping)))
                break;
            nextPing = now + std::chrono::milliseconds(kPingEveryMs);
        }
        // Records TLS already decrypted don't make the socket readable.
        if (!ctf::TlsPending(c->tls))
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
        int n = ctf::TlsRead(c->tls, buf, sizeof(buf));
        if (n == ctf::kTlsAgain)
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
            ChipLogError(chipTool, "Forwarder: bad frame from the forwarder");
            break;
        }
    }
    Drop(c.get());
}

void ForwarderStream::Impl::Dispatch(const Conn * c, uint8_t type, const uint8_t * b, size_t n)
{
    if (type == ctf::kFrameMatter)
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
    if (type != ctf::kFrameControl || n < 1)
        return;
    switch (b[0])
    {
    case ctf::kOpOpenOk:
    case ctf::kOpOpenErr: {
        ctf::OpenReplyMsg m;
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
    case ctf::kOpResult: {
        ctf::ResultMsg m;
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
    case ctf::kOpSign: {
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
            std::vector<uint8_t> body{ ctf::kOpSigned };
            if (out.empty())
            {
                if (!h)
                    ChipLogError(chipTool, "Forwarder: a signing request, but no signer here (use forwarder call with the fabric's storage)");
                // signed: req, status (ctf_proto.h)
                uint8_t r[4];
                ctf::Put16(r, req.size() >= 2 ? ctf::Get16(req.data()) : 0);
                ctf::Put16(r + 2, ctf::kErrSigner);
                body.insert(body.end(), r, r + 4);
            }
            else
            {
                body.insert(body.end(), out.begin(), out.end());
            }
            Send(ctf::kFrameControl, body.data(), body.size());
        }).detach();
        return;
    }
    case ctf::kOpEvent: {
        ctf::EventMsg m;
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
    case ctf::kOpError: {
        ctf::ErrorMsg m;
        if (m.Decode(b, n))
        {
            const uint16_t code = m.code;
            ChipLogError(chipTool, "Forwarder: the forwarder closed the stream: %s", ctf::ErrName(code));
            SetError(code == ctf::kErrBusy ? std::string("the forwarder is busy: all its connections are in use")
                                           : std::string("the forwarder closed the stream: ") + ctf::ErrName(code));
        }
        shutdown(c->fd, SHUT_RDWR); // the reader ends and drops it
        return;
    }
    default: // pong and anything newer
        return;
    }
}

uint16_t ForwarderStream::Impl::NewReq()
{
    return ++nextReq;
}

// One request and its answer: registers a pending entry in `table` under a new
// request ID (running `registered`, if given, under the same lock), sends the
// control message encode() builds for that ID and waits up to `timeout`; what
// prefixes its errors ("" for a call: its caller names it). kOk:
// `answer` holds the forwarder's answer. Any other result has recorded why
// (LastError, LastFailure), so the hint chip-tool-remote prints is about this
// request.
ForwarderStream::Result ForwarderStream::Impl::Exchange(PendingMap & table,
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
    const bool encoded = encode(req, body) && body.size() <= ctf::kMaxFrameBody;
    if (!encoded || !Send(ctf::kFrameControl, body.data(), body.size()))
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
        // Only this request fails (the forwarder may be busy, e.g. commissioning);
        // the reader's liveness check ends a dead stream.
        SetError(what + "no answer from the forwarder in time");
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

bool ForwarderStream::Configured()
{
    Impl & i = I();
    std::call_once(i.configOnce, [&i] { i.Configure(); });
    return i.configured;
}

uint32_t ForwarderStream::Epoch()
{
    return I().epoch.load();
}

bool ForwarderStream::SendMatter(const uint8_t * msg, size_t len)
{
    return I().Send(ctf::kFrameMatter, msg, len);
}

void ForwarderStream::SetMatterHandler(MatterHandler handler)
{
    Impl & i = I();
    std::lock_guard<std::mutex> l(i.mu);
    i.matter = std::move(handler);
}

ForwarderStream::Result ForwarderStream::Open(uint64_t node, uint16_t cloudLsid, uint64_t cloudNode, uint16_t & fwdLsid,
                                          uint8_t secretOut[32], uint16_t & code, uint32_t & epochOut)
{
    Impl & i = I();
    if (!Configured())
        return Result::kNotConfigured;
    uint8_t key[ctf::kKeyLen];
    auto encode = [&](uint16_t req, std::vector<uint8_t> & body) {
        ctf::OpenMsg m;
        m.req       = req;
        m.node      = node;
        m.cloudLsid = cloudLsid;
        m.cloudNode = cloudNode;
        body.resize(ctf::OpenMsg::kLen);
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
        fwdLsid = answer->v;
        if (!ctf::SessionSecret(key, node, cloudLsid, fwdLsid, secretOut))
        {
            i.SetError("session request: can't derive the session key");
            r = Result::kNoStream;
        }
    }
    memset(key, 0, sizeof(key));
    return r;
}

void ForwarderStream::Close(uint16_t cloudLsid, uint16_t fwdLsid)
{
    ctf::CloseMsg m;
    m.cloudLsid = cloudLsid;
    m.fwdLsid    = fwdLsid;
    uint8_t body[ctf::CloseMsg::kLen];
    m.Encode(body);
    I().Send(ctf::kFrameControl, body, sizeof(body));
}

ForwarderStream::Result ForwarderStream::Call(const std::string & name, const std::string & params, unsigned timeoutS,
                                          std::string & out)
{
    Impl & i = I();
    if (!Configured())
        return Result::kNotConfigured;
    if (name.empty() || name.size() > ctf::kMaxCallName)
    {
        i.SetError("the command name must be 1-" + std::to_string(ctf::kMaxCallName) + " characters");
        return Result::kRefused;
    }
    auto encode = [&](uint16_t req, std::vector<uint8_t> & body) {
        ctf::CallMsg m;
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

void ForwarderStream::SetSignHandler(SignHandler handler)
{
    std::lock_guard<std::mutex> l(I().mu);
    I().sign = std::move(handler);
}

void ForwarderStream::SetEventHandler(EventHandler handler)
{
    std::lock_guard<std::mutex> l(I().mu);
    I().event = std::move(handler);
}

std::string ForwarderStream::LastError()
{
    std::lock_guard<std::mutex> l(I().mu);
    return I().lastError;
}

ForwarderStream::Failure ForwarderStream::LastFailure()
{
    std::lock_guard<std::mutex> l(I().mu);
    return I().lastFailure;
}

} // namespace ForwarderClient
