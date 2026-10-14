// SPDX-License-Identifier: Apache-2.0

#include "mgw_server.h"
#include "mgw_log.h"
#include "mgw_server_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <memory>
#include <condition_variable>
#include <mutex>

#include <inet/IPAddress.h>
#include <lib/support/logging/CHIPLogging.h>
#include <platform/CHIPDeviceLayer.h>
#include <transport/raw/PeerAddress.h>

#include "mgw_keys.h"
#include "mgw_relay.h"
#include "mgw_tls.h"

namespace mgw {

namespace {

ServerConfig sConfig;
std::mutex sSecretLock;
uint32_t sSecretGen = 0; // bumped by SetServerSecret (under sSecretLock)
std::atomic<bool> sRunning{ false };
std::atomic<uint32_t> sNextConn{ 0 };
std::atomic<uint32_t> sAccepted{ 0 }, sRefused{ 0 }, sAuthFailures{ 0 }, sActive{ 0 }, sFramesIn{ 0 }, sFramesOut{ 0 },
    sBadFrames{ 0 };
// Handshakes in progress: unauthenticated peers can hold only these slots, so
// they can't keep the authenticated ones from the real client.
constexpr int kMaxHandshakes = 2;
std::atomic<int> sHandshaking{ 0 }, sAuthed{ 0 };

constexpr size_t kConnStack     = 6144; // about 3.3 KB in use, the TLS handshake included
constexpr size_t kCallStack     = 6144; // a gateway command (the controller's, the CA's)
constexpr uint32_t kHandshakeMs = 10000; // the whole TLS handshake, however slowly the peer sends
constexpr uint32_t kWriteMs     = 10000; // a frame not written by then: the connection is dropped
constexpr int kIdleS            = 300;
constexpr size_t kStackFrame    = 1500; // frames up to this size are written from the stack

void * Alloc(size_t n)
{
    return sConfig.alloc ? sConfig.alloc(n) : malloc(n);
}

void Release(void * p)
{
    if (p != nullptr)
    {
        sConfig.release ? sConfig.release(p) : free(p);
    }
}

struct Work
{
    void (*fn)(void *);
    void * arg;
    std::mutex m;
    std::condition_variable cv;
    bool done = false;
};

void Trampoline(intptr_t p)
{
    Work * w = reinterpret_cast<Work *>(p);
    w->fn(w->arg);
    // Notify under the lock: w is on the waiter's stack, and the waiter may
    // return (and free it) as soon as it sees done.
    std::lock_guard<std::mutex> l(w->m);
    w->done = true;
    w->cv.notify_one();
}

bool SendFrame(Tls * tls, uint8_t type, const uint8_t * body, size_t len)
{
    uint8_t small[kFrameHeaderLen + kStackFrame];
    uint8_t * buf = len <= kStackFrame ? small : static_cast<uint8_t *>(Alloc(kFrameHeaderLen + len));
    if (buf == nullptr || !FrameHeader(buf, type, len))
    {
        if (buf != small)
        {
            Release(buf);
        }
        return false;
    }
    memcpy(buf + kFrameHeaderLen, body, len);
    bool ok = TlsWrite(tls, buf, kFrameHeaderLen + len, kWriteMs);
    if (buf != small)
    {
        Release(buf);
    }
    if (ok)
    {
        sFramesOut++;
    }
    return ok;
}

bool SendError(Tls * tls, uint16_t code)
{
    ErrorMsg m;
    m.code = code;
    uint8_t b[ErrorMsg::kLen];
    m.Encode(b);
    return SendFrame(tls, kFrameControl, b, sizeof(b));
}

// Frame writes to one connection, from its own thread and from command tasks
// (which may outlive the connection: they hold a reference, and a write after
// Close() is dropped).
class Writer
{
public:
    explicit Writer(int fd) : mFd(fd) {}
    // Once the handshake is done (frames before it are dropped).
    void SetTls(Tls * tls)
    {
        std::lock_guard<std::mutex> l(mLock);
        mTls = tls;
    }
    bool Send(uint8_t type, const uint8_t * body, size_t len)
    {
        std::lock_guard<std::mutex> l(mLock);
        if (!mClosed && mTls != nullptr && SendFrame(mTls, type, body, len))
        {
            return true;
        }
        Fail();
        return false;
    }
    bool Error(uint16_t code)
    {
        std::lock_guard<std::mutex> l(mLock);
        return !mClosed && mTls != nullptr && SendError(mTls, code);
    }
    // After Close() no write is in progress or starts: the TLS context can go.
    void Close()
    {
        std::lock_guard<std::mutex> l(mLock);
        mClosed = true;
    }
    // Ends the connection (its thread sees the socket close).
    void Disconnect()
    {
        std::lock_guard<std::mutex> l(mLock);
        if (!mClosed)
        {
            shutdown(mFd, SHUT_RDWR);
        }
    }

private:
    // A write that failed (or timed out) leaves the stream unusable: end it.
    void Fail()
    {
        if (!mClosed && mTls != nullptr)
        {
            shutdown(mFd, SHUT_RDWR);
        }
    }

    std::mutex mLock;
    const int mFd;
    Tls * mTls   = nullptr;
    bool mClosed = false;

public:
    std::atomic<int> calls{ 0 }; // this connection's calls in progress
};

// Calls in progress: each has a task (and its stack) until it answers, and
// some wait minutes (commissioning, icd_wait).
constexpr int kMaxCallsPerConn = 3;
constexpr int kMaxCalls        = 6;
std::atomic<int> sCalls{ 0 };

// Connections by ID, so the gateway can ask the cloud controller of one of
// them (the signer) and route its answer.
struct Registered
{
    uint32_t id = 0;
    std::shared_ptr<Writer> out;
};
constexpr size_t kMaxRegistered = 8;
std::mutex sRegLock;
Registered sReg[kMaxRegistered];
SignedHandler sSignedHandler;
thread_local uint32_t tCallConn;

void Register(uint32_t id, const std::shared_ptr<Writer> & out)
{
    std::lock_guard<std::mutex> l(sRegLock);
    for (auto & r : sReg)
    {
        if (r.id == 0)
        {
            r.id  = id;
            r.out = out;
            return;
        }
    }
}

void Unregister(uint32_t id)
{
    std::lock_guard<std::mutex> l(sRegLock);
    for (auto & r : sReg)
    {
        if (r.id == id)
        {
            r.id = 0;
            r.out.reset();
        }
    }
}

// A result frame for call `req` (json: n bytes, not NUL-terminated).
bool SendResult(Writer & out, uint16_t req, const char * json, size_t n)
{
    ResultMsg m;
    m.req     = req;
    m.json    = json;
    m.jsonLen = n;
    uint8_t * body = static_cast<uint8_t *>(Alloc(m.Len()));
    bool ok        = body != nullptr && m.Encode(body, m.Len()) && out.Send(kFrameControl, body, m.Len());
    Release(body);
    return ok;
}

bool SendResult(Writer & out, uint16_t req, const char * json)
{
    return SendResult(out, req, json, strlen(json));
}

struct CallJob
{
    std::shared_ptr<Writer> out;
    uint32_t conn;
    uint16_t req;
    char name[kMaxCallName + 1];
    char * params; // Alloc'd, NUL-terminated
};

void CallMain(void * arg)
{
    CallJob * job = static_cast<CallJob *>(arg);
    static constexpr size_t kOut = kMaxFrameBody - ResultMsg::kHeaderLen;
    char * result = static_cast<char *>(Alloc(kOut));
    if (result != nullptr)
    {
        result[0] = 0;
        tCallConn = job->conn;
        sConfig.call(job->name, job->params, result, kOut);
        tCallConn = 0;
        SendResult(*job->out, job->req, result, strnlen(result, kOut));
        Release(result);
    }
    job->out->calls--;
    sCalls--;
    Release(job->params);
    job->~CallJob();
    Release(job);
}

bool ValidName(const uint8_t * n, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        const uint8_t c = n[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_'))
        {
            return false;
        }
    }
    return true;
}

class Connection
{
public:
    Connection(int fd) : mTcp(fd), mOut(std::make_shared<Writer>(fd)), mId(++sNextConn) {}

    void Run();

private:
    bool Handshake();
    bool OpenBridge();
    bool HandleControl(const uint8_t * b, size_t len);
    void Cleanup();

    int mTcp;
    std::shared_ptr<Writer> mOut;
    int mUdp = -1;
    uint16_t mBridgePort = 0;
    const uint32_t mId;
    bool mAuthed = false; // counted in sAuthed
    Tls * mTls = nullptr; // set once the handshake succeeded
    uint8_t mConnKey[kKeyLen];
    FrameReader mReader;
};

bool Connection::OpenBridge()
{
    mUdp = socket(AF_INET, SOCK_DGRAM, 0);
    if (mUdp < 0)
    {
        return false;
    }
    sockaddr_in a = {};
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port        = 0;
    if (bind(mUdp, reinterpret_cast<sockaddr *>(&a), sizeof(a)) != 0)
    {
        return false;
    }
    socklen_t al = sizeof(a);
    if (getsockname(mUdp, reinterpret_cast<sockaddr *>(&a), &al) != 0)
    {
        return false;
    }
    mBridgePort = ntohs(a.sin_port);
    sockaddr_in chip = {};
    chip.sin_family      = AF_INET;
    chip.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    chip.sin_port        = htons(sConfig.chipUdpPort);
    return connect(mUdp, reinterpret_cast<sockaddr *>(&chip), sizeof(chip)) == 0;
}

struct OpenArgs
{
    uint32_t conn;
    uint64_t node;
    uint16_t cloudLsid;
    uint64_t cloudNode;
    uint16_t bridgePort;
    const uint8_t * connKey;
    uint16_t gwLsid;
    ErrCode result;
};

void OpenInChipTask(void * p)
{
    auto * a = static_cast<OpenArgs *>(p);
    chip::Inet::IPAddress loopback;
    chip::Inet::IPAddress::FromString("127.0.0.1", loopback);
    a->result = Relay::Instance().OpenSession(a->conn, a->node, a->cloudLsid, a->cloudNode,
                                              chip::Transport::PeerAddress::UDP(loopback, a->bridgePort), a->connKey, a->gwLsid);
}

struct CloseArgs
{
    uint32_t conn;
    uint16_t gwLsid; // 0: the whole connection
};

void CloseInChipTask(void * p)
{
    auto * a = static_cast<CloseArgs *>(p);
    if (a->gwLsid == 0)
    {
        Relay::Instance().CloseConnection(a->conn);
    }
    else
    {
        Relay::Instance().CloseSession(a->conn, a->gwLsid);
    }
}

bool Connection::HandleControl(const uint8_t * b, size_t len)
{
    if (len < 1)
    {
        return false;
    }
    switch (b[0])
    {
    case kOpOpen: {
        OpenMsg m;
        if (!m.Decode(b, len))
        {
            return false;
        }
        OpenArgs a = { mId, m.node, m.cloudLsid, m.cloudNode, mBridgePort, mConnKey, 0, kErrInternal };
        RunInChipTask(OpenInChipTask, &a);
        OpenReplyMsg r;
        r.ok    = a.result == kErrNone;
        r.req   = m.req;
        r.value = r.ok ? a.gwLsid : static_cast<uint16_t>(a.result);
        uint8_t reply[OpenReplyMsg::kLen];
        r.Encode(reply);
        return mOut->Send(kFrameControl, reply, sizeof(reply));
    }
    case kOpClose: {
        CloseMsg m;
        if (!m.Decode(b, len))
        {
            return false;
        }
        CloseArgs a = { mId, m.gwLsid };
        if (a.gwLsid != 0)
        {
            RunInChipTask(CloseInChipTask, &a);
        }
        return true;
    }
    case kOpCall: {
        CallMsg m;
        if (!m.Decode(b, len))
        {
            return false;
        }
        if (sConfig.call == nullptr)
        {
            return SendResult(*mOut, m.req,
                              "{\"ok\":false,\"error\":{\"code\":\"unsupported\",\"message\":\"no gateway commands here\"}}");
        }
        if (m.nameLen == 0 || m.nameLen > kMaxCallName || !ValidName(reinterpret_cast<const uint8_t *>(m.name), m.nameLen))
        {
            return SendResult(*mOut, m.req,
                              "{\"ok\":false,\"error\":{\"code\":\"unknown_command\",\"message\":\"not a gateway command "
                              "name\"}}");
        }
        // Counted here, on the connection's thread: a burst can't overshoot.
        if (mOut->calls.load() >= kMaxCallsPerConn || sCalls.load() >= kMaxCalls)
        {
            return SendResult(*mOut, m.req,
                              "{\"ok\":false,\"error\":{\"code\":\"busy\",\"message\":\"too many gateway calls in "
                              "progress; wait for one to answer\"}}");
        }
        void * mem    = Alloc(sizeof(CallJob));
        CallJob * job = mem != nullptr ? new (mem) CallJob : nullptr;
        if (job == nullptr)
        {
            return false;
        }
        job->out  = mOut;
        job->conn = mId;
        job->req  = m.req;
        memcpy(job->name, m.name, m.nameLen);
        job->name[m.nameLen] = 0;
        job->params          = static_cast<char *>(Alloc(m.paramsLen + 1));
        if (job->params == nullptr)
        {
            job->~CallJob();
            Release(job);
            return false;
        }
        memcpy(job->params, m.params, m.paramsLen);
        job->params[m.paramsLen] = 0;
        mOut->calls++;
        sCalls++;
        if (!sConfig.spawn(CallMain, job, "matter_gw_call", kCallStack))
        {
            mOut->calls--;
            sCalls--;
            Release(job->params);
            job->~CallJob();
            Release(job);
            return false;
        }
        return true;
    }
    case kOpPing: {
        PingMsg m;
        if (!m.Decode(b, len))
        {
            return false;
        }
        m.pong = true;
        uint8_t pong[PingMsg::kLen];
        m.Encode(pong);
        return mOut->Send(kFrameControl, pong, sizeof(pong));
    }
    case kOpSigned: {
        SignedHandler h;
        {
            std::lock_guard<std::mutex> l(sRegLock);
            h = sSignedHandler;
        }
        if (h != nullptr)
        {
            h(mId, b + 1, len - 1);
        }
        return true;
    }
    case kOpPong:
        return true;
    default:
        mOut->Error(kErrBadFrame);
        return false;
    }
}

// The client's PSK identity -> the PSK, from the current secret (so a
// handshake after a rotation needs the new one); ctx gets that secret's
// generation.
bool LookupPsk(void * ctx, const uint8_t * identity, size_t len, uint8_t psk[kKeyLen])
{
    char expect[kIdentityLen];
    std::lock_guard<std::mutex> l(sSecretLock);
    *static_cast<uint32_t *>(ctx) = sSecretGen;
    return sConfig.secretLen >= kMinSecretLen && len == kIdentityLen - 1 &&
        TlsIdentity(sConfig.secret, sConfig.secretLen, expect) &&
        ConstantTimeEqual(reinterpret_cast<const uint8_t *>(expect), identity, len) &&
        TlsPsk(sConfig.secret, sConfig.secretLen, psk);
}

bool Connection::Handshake()
{
    TlsFail why;
    char detail[48] = "";
    uint32_t gen    = 0;
    Tls * tls       = TlsAccept(mTcp, LookupPsk, &gen, kHandshakeMs, why, detail, sizeof(detail));
    if (tls == nullptr)
    {
        if (why == TlsFail::kUnknownSecret)
        {
            sAuthFailures++;
            MGW_ERR("conn %u: a client with an unknown secret", static_cast<unsigned>(mId));
        }
        else
        {
            MGW_ERR("conn %u: TLS handshake failed (%s%s%s)", static_cast<unsigned>(mId),
                    why == TlsFail::kTimeout ? "timeout"
                        : why == TlsFail::kClosed ? "closed"
                        : why == TlsFail::kProtocol ? "ALPN"
                                                    : "error",
                    detail[0] ? " " : "", detail);
        }
        return false;
    }
    if (!TlsExportConnKey(tls, mConnKey))
    {
        MGW_ERR("conn %u: no exported key", static_cast<unsigned>(mId));
        TlsFree(tls);
        return false;
    }
    mTls = tls;
    mOut->SetTls(tls);
    if (sAuthed.fetch_add(1) >= sConfig.maxConnections)
    {
        sAuthed--;
        sRefused++;
        mOut->Error(kErrBusy);
        return false;
    }
    mAuthed = true;
    // Registered under the secret's lock: a rotation either sees this
    // connection (and disconnects it) or comes first (and the old secret's
    // handshake is refused here).
    std::lock_guard<std::mutex> l(sSecretLock);
    if (gen != sSecretGen)
    {
        MGW_ERR("conn %u: the secret changed during the handshake", static_cast<unsigned>(mId));
        return false;
    }
    Register(mId, mOut);
    return true;
}

void Connection::Run()
{
    int one = 1;
    setsockopt(mTcp, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(mTcp, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));

    bool ok = Handshake(); // it logs why not
    sHandshaking--;
    if (ok && !OpenBridge())
    {
        MGW_ERR("conn %u: loopback bridge failed (%d)", static_cast<unsigned>(mId), errno);
        mOut->Error(kErrInternal);
        ok = false;
    }
    if (ok)
    {
        MGW_LOG("conn %u: authenticated (bridge port %u)", static_cast<unsigned>(mId), mBridgePort);
        uint8_t * buf = static_cast<uint8_t *>(Alloc(kFrameHeaderLen + kMaxFrameBody));
        for (; buf != nullptr;)
        {
            // Records TLS already decrypted don't make the socket readable.
            const bool pending = TlsPending(mTls);
            fd_set rd;
            FD_ZERO(&rd);
            FD_SET(mTcp, &rd);
            FD_SET(mUdp, &rd);
            const int maxfd = (mTcp > mUdp ? mTcp : mUdp) + 1;
            timeval tv      = { pending ? 0 : kIdleS, 0 };
            int n           = select(maxfd, &rd, nullptr, nullptr, &tv);
            if (n < 0 && errno == EINTR)
            {
                continue;
            }
            if (n < 0 || (n == 0 && !pending))
            {
                MGW_LOG("conn %u: idle, closing", static_cast<unsigned>(mId));
                break;
            }
            if (n > 0 && FD_ISSET(mUdp, &rd))
            {
                ssize_t r = recv(mUdp, buf, kFrameHeaderLen + kMaxFrameBody, 0);
                if (r > 0 && !mOut->Send(kFrameMatter, buf, static_cast<size_t>(r)))
                {
                    break;
                }
            }
            if (pending || (n > 0 && FD_ISSET(mTcp, &rd)))
            {
                int r = TlsRead(mTls, buf, kFrameHeaderLen + kMaxFrameBody);
                if (r == kTlsAgain)
                {
                    continue;
                }
                if (r <= 0)
                {
                    break;
                }
                bool fine = true;
                size_t at = 0;
                while (fine && at < static_cast<size_t>(r))
                {
                    at += mReader.Feed(buf + at, static_cast<size_t>(r) - at);
                    if (mReader.Bad())
                    {
                        sBadFrames++;
                        mOut->Error(kErrBadFrame);
                        fine = false;
                        break;
                    }
                    if (!mReader.Ready())
                    {
                        continue;
                    }
                    sFramesIn++;
                    if (mReader.Type() == kFrameControl)
                    {
                        fine = HandleControl(mReader.Body(), mReader.BodyLen());
                    }
                    else if (mReader.Type() == kFrameMatter)
                    {
                        send(mUdp, mReader.Body(), mReader.BodyLen(), 0);
                    }
                    else
                    {
                        fine = false;
                    }
                    if (!fine)
                    {
                        // A malformed frame (or a write that failed): say so, then close.
                        sBadFrames++;
                        mOut->Error(kErrBadFrame);
                    }
                    mReader.Consume();
                }
                if (!fine)
                {
                    break;
                }
            }
        }
        Release(buf);
    }
    Cleanup();
}

void Connection::Cleanup()
{
    if (mTls != nullptr)
    {
        CloseArgs a = { mId, 0 };
        RunInChipTask(CloseInChipTask, &a);
        MGW_LOG("conn %u closed", static_cast<unsigned>(mId));
    }
    Unregister(mId);
    mOut->Close();
    TlsFree(mTls);
    memset(mConnKey, 0, sizeof(mConnKey));
    if (mUdp >= 0)
    {
        close(mUdp);
    }
    close(mTcp);
    if (mAuthed)
    {
        sAuthed--;
    }
    sActive--;
}

void ConnectionMain(void * arg)
{
    Connection * c = static_cast<Connection *>(arg);
    c->Run();
    c->~Connection();
    Release(c);
}

} // namespace

void StartConnection(int fd)
{
    sAccepted++;
    // Over the limit: closed before any TLS (the client says "busy, or ...").
    if (sHandshaking.load() >= kMaxHandshakes ||
        static_cast<int>(sActive.load()) >= sConfig.maxConnections + kMaxHandshakes)
    {
        sRefused++;
        close(fd);
        return;
    }
    void * mem     = Alloc(sizeof(Connection));
    Connection * c = mem ? new (mem) Connection(fd) : nullptr;
    if (c == nullptr)
    {
        close(fd);
        return;
    }
    sActive++; // here, on the listener's task: a burst of accepts can't overshoot the limit
    sHandshaking++;
    if (!sConfig.spawn(ConnectionMain, c, "matter_gw_conn", kConnStack))
    {
        sHandshaking--;
        sActive--;
        sRefused++;
        close(fd);
        c->~Connection();
        Release(c);
    }
}

const ServerConfig & ServerSettings()
{
    return sConfig;
}

void RunInChipTask(void (*fn)(void *), void * arg)
{
    Work w;
    w.fn  = fn;
    w.arg = arg;
    // The CHIP queue can be full for a moment (a burst of datagrams): retry,
    // since callers rely on the work running (closing a connection's sessions).
    for (int i = 0; chip::DeviceLayer::PlatformMgr().ScheduleWork(Trampoline, reinterpret_cast<intptr_t>(&w)) != CHIP_NO_ERROR; i++)
    {
        if (i % 50 == 0)
        {
            MGW_ERR("the CHIP queue is full; retrying");
        }
        usleep(20 * 1000);
    }
    std::unique_lock<std::mutex> l(w.m);
    w.cv.wait(l, [&] { return w.done; });
}

bool StartServer(const ServerConfig & config)
{
    if (sRunning.exchange(true))
    {
        return true;
    }
    {
        std::lock_guard<std::mutex> l(sSecretLock);
        sConfig = config;
        // Every authenticated connection needs a registry slot (events, the signer).
        if (sConfig.maxConnections > static_cast<int>(kMaxRegistered))
        {
            sConfig.maxConnections = static_cast<int>(kMaxRegistered);
        }
    }
    if (config.anyAddress && OpenListener(nullptr, 0) < 0)
    {
        sRunning = false;
        return false;
    }
    MGW_LOG("CHIP UDP %u", config.chipUdpPort);
    return true;
}

void SetServerSecret(const uint8_t * secret, size_t len)
{
    std::lock_guard<std::mutex> l(sSecretLock);
    if (len > kMaxSecretLen)
    {
        len = kMaxSecretLen;
    }
    memset(sConfig.secret, 0, sizeof(sConfig.secret));
    memcpy(sConfig.secret, secret, len);
    sConfig.secretLen = len;
    sSecretGen++;
}

ServerStats GetServerStats()
{
    return ServerStats{ sAccepted, sRefused, sAuthFailures, sActive, sFramesIn, sFramesOut, sBadFrames };
}

bool ServerRunning()
{
    return sRunning;
}

uint32_t CurrentCallConnection()
{
    return tCallConn;
}

bool SendToConnection(uint32_t conn, uint8_t type, const uint8_t * body, size_t len)
{
    std::shared_ptr<Writer> out;
    {
        std::lock_guard<std::mutex> l(sRegLock);
        for (auto & r : sReg)
        {
            if (r.id == conn && conn != 0)
            {
                out = r.out;
            }
        }
    }
    return out && out->Send(type, body, len);
}

size_t SendToAllConnections(uint8_t type, const uint8_t * body, size_t len)
{
    std::shared_ptr<Writer> outs[kMaxRegistered];
    {
        std::lock_guard<std::mutex> l(sRegLock);
        for (size_t i = 0; i < kMaxRegistered; i++)
        {
            if (sReg[i].id != 0)
            {
                outs[i] = sReg[i].out;
            }
        }
    }
    size_t n = 0;
    for (auto & out : outs)
    {
        n += out && out->Send(type, body, len) ? 1 : 0;
    }
    return n;
}

size_t DisconnectAll()
{
    std::shared_ptr<Writer> outs[kMaxRegistered];
    {
        std::lock_guard<std::mutex> l(sRegLock);
        for (size_t i = 0; i < kMaxRegistered; i++)
        {
            outs[i] = sReg[i].out;
        }
    }
    size_t n = 0;
    for (auto & out : outs)
    {
        if (out)
        {
            out->Disconnect();
            n++;
        }
    }
    return n;
}

size_t SendEvent(uint8_t kind, uint64_t node)
{
    EventMsg m;
    m.kind = kind;
    m.node = node;
    uint8_t b[EventMsg::kLen];
    m.Encode(b);
    return SendToAllConnections(kFrameControl, b, sizeof(b));
}

void SetSignedHandler(SignedHandler handler)
{
    std::lock_guard<std::mutex> l(sRegLock);
    sSignedHandler = handler;
}

} // namespace mgw
