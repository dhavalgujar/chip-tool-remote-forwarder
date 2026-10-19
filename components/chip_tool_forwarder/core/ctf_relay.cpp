// SPDX-License-Identifier: Apache-2.0

#include "ctf_relay.h"
#include "ctf_keys.h"
#include "ctf_log.h"
#include "ctf_session.h"

#include <string.h>

#include <app/InteractionModelEngine.h>
#include <app/MessageDef/InvokeRequestMessage.h>
#include <app/MessageDef/InvokeResponseMessage.h>
#include <app/MessageDef/ReportDataMessage.h>
#include <app/MessageDef/StatusResponseMessage.h>
#include <app/MessageDef/SubscribeResponseMessage.h>
#include <app/MessageDef/WriteRequestMessage.h>
#include <app/OperationalSessionSetup.h>
#include <app/StatusResponse.h>
#include <crypto/CHIPCryptoPAL.h>
#include <lib/core/CHIPCallback.h>
#include <lib/core/TLV.h>
#include <lib/support/logging/CHIPLogging.h>
#include <messaging/ExchangeHolder.h>
#include <platform/CHIPDeviceLayer.h>
#include <protocols/interaction_model/Constants.h>
#include <system/TLVPacketBufferBackingStore.h>

using namespace chip;
using chip::Protocols::InteractionModel::MsgType;
using chip::Protocols::InteractionModel::Status;

namespace ctf {

namespace {

template <class Parser>
CHIP_ERROR ParseMessage(const System::PacketBufferHandle & payload, System::PacketBufferTLVReader & reader, Parser & parser)
{
    reader.Init(payload.Retain());
    return parser.Init(reader);
}

bool IsIM(const PayloadHeader & h)
{
    return h.HasProtocol(Protocols::InteractionModel::Id);
}

/*
 * Every cloud client reaches the node as the forwarder, so a subscribe request
 * with KeepSubscriptions=false would end the subscriptions of the others (and
 * the forwarder's own). Flip it to true in place: in TLV the boolean is the
 * element type of the control byte (context tag 0: 0x28 false, 0x29 true).
 */
void ForceKeepSubscriptions(System::PacketBufferHandle & payload)
{
    VerifyOrReturn(!payload.IsNull() && !payload->HasChainedBuffer());
    uint8_t * start = payload->Start();
    TLV::TLVReader r;
    r.Init(start, payload->DataLength());
    VerifyOrReturn(r.Next(TLV::kTLVType_Structure, TLV::AnonymousTag()) == CHIP_NO_ERROR);
    TLV::TLVType outer;
    VerifyOrReturn(r.EnterContainer(outer) == CHIP_NO_ERROR);
    while (r.Next() == CHIP_NO_ERROR)
    {
        if (r.GetTag() == TLV::ContextTag(0) && r.GetType() == TLV::kTLVType_Boolean)
        {
            size_t off = static_cast<size_t>(r.GetReadPoint() - start);
            if (off >= 2 && start[off - 2] == 0x28 && start[off - 1] == 0x00)
            {
                start[off - 2] = 0x29;
                CTF_LOG("subscribe with KeepSubscriptions=false kept as true");
            }
            return;
        }
    }
}

} // namespace

/*
 * One relayed exchange: the cloud's exchange and the node's exchange, each
 * kept open while the other side owes an answer.
 */
class Pair : public Messaging::ExchangeDelegate
{
public:
    enum class Origin : uint8_t
    {
        kCloud,
        kDevice,
    };

    Pair(Relay & relay, Origin origin, uint16_t fwdLsid, NodeId node) :
        mRelay(relay), mOrigin(origin), mFwdLsid(fwdLsid), mNode(node), mCloud(*this), mDev(*this),
        mOnConnected(OnConnected, this), mOnFailure(OnConnectFailure, this)
    {
        mRelay.mPairs++;
    }

    ~Pair() override
    {
        mOnConnected.Cancel();
        mOnFailure.Cancel();
        DeviceLayer::SystemLayer().CancelTimer(RetryToCloud, this);
        mRelay.mPairs--;
    }

    CHIP_ERROR OnMessageReceived(Messaging::ExchangeContext * ec, const PayloadHeader & header,
                                 System::PacketBufferHandle && payload) override
    {
        Scope scope(*this);
        if (!mStarted)
        {
            mStarted = true;
            (mOrigin == Origin::kCloud ? mCloud : mDev).Grab(ec);
            mFirst = header.GetMessageType();
        }
        if (!IsIM(header) || payload.IsNull())
        {
            Finish();
            return CHIP_NO_ERROR;
        }
        const bool fromCloud = mCloud.Contains(ec);
        const uint8_t type   = header.GetMessageType();

        // Copy into a fresh buffer: the stack needs header room in front and
        // room for the MIC behind.
        System::PacketBufferHandle msg = System::PacketBufferHandle::NewWithData(payload->Start(), payload->DataLength(),
                                                                                 Crypto::CHIP_CRYPTO_AEAD_MIC_LENGTH_BYTES);
        if (msg.IsNull())
        {
            Finish();
            return CHIP_NO_ERROR;
        }
        if (fromCloud && type == to_underlying(MsgType::SubscribeRequest))
        {
            ForceKeepSubscriptions(msg);
        }

        const bool expect = Classify(fromCloud, type, msg);
        if (expect)
        {
            ec->WillSendMessage(); // the answer comes back on this exchange
        }
        if (fromCloud)
        {
            mLastCloud = type;
            mRelay.mStats.messagesToDevice++;
            ToDevice(type, std::move(msg), expect);
        }
        else
        {
            mLastDev = type;
            mRelay.mStats.messagesToCloud++;
            ToCloud(type, std::move(msg), expect);
        }
        return CHIP_NO_ERROR;
    }

    void OnResponseTimeout(Messaging::ExchangeContext * ec) override
    {
        Scope scope(*this);
        CTF_ERR("node 0x" ChipLogFormatX64 ": no answer from the %s", ChipLogValueX64(mNode),
                mCloud.Contains(ec) ? "cloud" : "node");
        mRelay.mStats.timeouts++;
        FailCloud(Status::Failure);
        Finish();
    }

    void OnExchangeClosing(Messaging::ExchangeContext * ec) override
    {
        Scope scope(*this);
        // The holder keeps an exchange that closed while a send was expected
        // (its session went away): this pair can't complete.
        if (mCloud.Contains(ec) || mDev.Contains(ec))
        {
            Finish();
            return;
        }
        if (mStarted && !mCloud && !mDev && !mConnecting)
        {
            mDone = true;
        }
    }

private:
    // Deletes the pair once the outermost callback returns.
    struct Scope
    {
        explicit Scope(Pair & p) : pair(p) { pair.mDepth++; }
        ~Scope()
        {
            if (--pair.mDepth == 0 && pair.mDone)
            {
                delete &pair;
            }
        }
        Pair & pair;
    };

    void Finish()
    {
        mDone = true;
        mOnConnected.Cancel();
        mOnFailure.Cancel();
        DeviceLayer::SystemLayer().CancelTimer(RetryToCloud, this);
        mConnecting = false;
        mCloud.Release();
        mDev.Release();
    }

    // The cloud waits for an answer this pair can't relay: give it a status
    // now rather than leave it to its own timeout.
    void FailCloud(Status status)
    {
        if (mCloud && mCloud->IsSendExpected())
        {
            TEMPORARY_RETURN_IGNORED app::StatusResponse::Send(status, mCloud.Get(), false);
        }
    }

    // True when the message's receiver will answer on the same exchange.
    bool Classify(bool fromCloud, uint8_t type, const System::PacketBufferHandle & msg)
    {
        System::PacketBufferTLVReader reader;
        if (fromCloud)
        {
            switch (static_cast<MsgType>(type))
            {
            case MsgType::ReadRequest:
            case MsgType::SubscribeRequest:
            case MsgType::TimedRequest:
                return true;
            case MsgType::WriteRequest: {
                app::WriteRequestMessage::Parser p;
                bool suppress = false, more = false;
                if (ParseMessage(msg, reader, p) == CHIP_NO_ERROR)
                {
                    TEMPORARY_RETURN_IGNORED p.GetSuppressResponse(&suppress);
                    TEMPORARY_RETURN_IGNORED p.GetMoreChunkedMessages(&more);
                }
                mWriteMore = more;
                return !suppress;
            }
            case MsgType::InvokeCommandRequest: {
                app::InvokeRequestMessage::Parser p;
                bool suppress = false;
                if (ParseMessage(msg, reader, p) == CHIP_NO_ERROR)
                {
                    TEMPORARY_RETURN_IGNORED p.GetSuppressResponse(&suppress);
                }
                return !suppress;
            }
            case MsgType::StatusResponse: {
                app::StatusResponseMessage::Parser p;
                Status status = Status::Failure;
                if (ParseMessage(msg, reader, p) == CHIP_NO_ERROR)
                {
                    TEMPORARY_RETURN_IGNORED p.GetStatus(status);
                }
                if (mOrigin == Origin::kDevice && status == Status::InvalidSubscription)
                {
                    mRelay.ForgetSubscription(mNode, mSubscriptionId);
                }
                // Any other status ends the interaction: the node won't answer it.
                return status == Status::Success &&
                    (mDevMore ||
                     (mFirst == to_underlying(MsgType::SubscribeRequest) && !mPrimed &&
                      mLastDev == to_underlying(MsgType::ReportData)));
            }
            default:
                return false;
            }
        }
        switch (static_cast<MsgType>(type))
        {
        case MsgType::ReportData: {
            app::ReportDataMessage::Parser p;
            bool suppress = false, more = false;
            if (ParseMessage(msg, reader, p) == CHIP_NO_ERROR)
            {
                TEMPORARY_RETURN_IGNORED p.GetSuppressResponse(&suppress);
                TEMPORARY_RETURN_IGNORED p.GetMoreChunkedMessages(&more);
            }
            mDevMore = more;
            return more || !suppress;
        }
        case MsgType::InvokeCommandResponse: {
            app::InvokeResponseMessage::Parser p;
            bool more = false;
            if (ParseMessage(msg, reader, p) == CHIP_NO_ERROR)
            {
                TEMPORARY_RETURN_IGNORED p.GetMoreChunkedMessages(&more);
            }
            mDevMore = more;
            return more;
        }
        case MsgType::WriteResponse:
            mDevMore = false;
            return mWriteMore;
        case MsgType::SubscribeResponse: {
            app::SubscribeResponseMessage::Parser p;
            SubscriptionId id    = 0;
            uint16_t maxInterval = 0;
            if (ParseMessage(msg, reader, p) == CHIP_NO_ERROR && p.GetSubscriptionId(&id) == CHIP_NO_ERROR)
            {
                TEMPORARY_RETURN_IGNORED p.GetMaxInterval(&maxInterval);
                mRelay.RecordSubscription(mNode, id, mFwdLsid, maxInterval);
            }
            mPrimed  = true;
            mDevMore = false;
            return false;
        }
        case MsgType::StatusResponse: {
            app::StatusResponseMessage::Parser p;
            Status status = Status::Failure;
            if (ParseMessage(msg, reader, p) == CHIP_NO_ERROR)
            {
                TEMPORARY_RETURN_IGNORED p.GetStatus(status);
            }
            mDevMore = false;
            return mLastCloud == to_underlying(MsgType::TimedRequest) && status == Status::Success;
        }
        default:
            return false;
        }
    }

    void ToDevice(uint8_t type, System::PacketBufferHandle && msg, bool expect)
    {
        if (mDev)
        {
            Send(mDev, type, std::move(msg), expect);
            return;
        }
        // First message: get (or set up) the forwarder's CASE session with the node.
        mPendingType   = type;
        mPending       = std::move(msg);
        mPendingExpect = expect;
        mConnecting    = true;
        CHIP_ERROR err = mRelay.mController->GetConnectedDevice(mNode, &mOnConnected, &mOnFailure);
        if (err != CHIP_NO_ERROR)
        {
            OnConnectFailure(this, ScopedNodeId(mNode, mRelay.mController->GetFabricIndex()), err);
        }
    }

    void ToCloud(uint8_t type, System::PacketBufferHandle && msg, bool expect)
    {
        if (!mCloud)
        {
            Relay::CloudSession * s = mRelay.FindSession(mFwdLsid);
            Messaging::ExchangeContext * ec = nullptr;
            if (s != nullptr && s->holder)
            {
                ec = mRelay.mController->ExchangeMgr()->NewContext(s->holder.Get().Value(), this);
            }
            if (ec == nullptr && s != nullptr && s->holder && mRetries < kMaxRetries)
            {
                // The session is there but no exchange now (the pool is full,
                // or the session is inactive for a moment): try again shortly
                // rather than end the subscription. The node waits for our answer.
                mRetries++;
                mPendingType   = type;
                mPending       = std::move(msg);
                mPendingExpect = expect;
                if (DeviceLayer::SystemLayer().StartTimer(System::Clock::Milliseconds32(kRetryMs), RetryToCloud, this) ==
                    CHIP_NO_ERROR)
                {
                    return;
                }
                msg = std::move(mPending);
            }
            if (ec == nullptr)
            {
                // Nobody to report to any more: end the subscription on the node.
                mRelay.ForgetSubscription(mNode, mSubscriptionId);
                if (mDev && expect)
                {
                    TEMPORARY_RETURN_IGNORED app::StatusResponse::Send(Status::InvalidSubscription, mDev.Get(), false);
                }
                Finish();
                return;
            }
            mCloud.Grab(ec);
        }
        Send(mCloud, type, std::move(msg), expect);
    }

    void Send(Messaging::ExchangeHolder & to, uint8_t type, System::PacketBufferHandle && msg, bool expect)
    {
        if (expect)
        {
            to->SetResponseTimeout(System::Clock::Milliseconds32(Relay::kResponseTimeoutMs));
        }
        CHIP_ERROR err = to->SendMessage(Protocols::InteractionModel::Id, type, std::move(msg),
                                         expect ? Messaging::SendFlags(Messaging::SendMessageFlags::kExpectResponse)
                                                : Messaging::SendFlags(Messaging::SendMessageFlags::kNone));
        if (err != CHIP_NO_ERROR)
        {
            CTF_ERR("node 0x" ChipLogFormatX64 ": send to the %s failed: %" CHIP_ERROR_FORMAT,
                    ChipLogValueX64(mNode), &to == &mCloud ? "cloud" : "node", err.Format());
            mRelay.mStats.sendFailures++;
            if (&to == &mDev)
            {
                FailCloud(Status::Failure);
            }
            Finish();
        }
    }

    static void RetryToCloud(System::Layer *, void * context)
    {
        Pair * self = static_cast<Pair *>(context);
        Scope scope(*self);
        if (!self->mDone)
        {
            self->ToCloud(self->mPendingType, std::move(self->mPending), self->mPendingExpect);
        }
    }

    static void OnConnected(void * context, Messaging::ExchangeManager & exchangeMgr, const SessionHandle & session)
    {
        Pair * self = static_cast<Pair *>(context);
        Scope scope(*self);
        self->mConnecting = false;
        if (self->mDone)
        {
            return;
        }
        Messaging::ExchangeContext * ec = exchangeMgr.NewContext(session, self);
        if (ec == nullptr)
        {
            self->FailCloud(Status::Busy);
            self->Finish();
            return;
        }
        self->mDev.Grab(ec);
        self->Send(self->mDev, self->mPendingType, std::move(self->mPending), self->mPendingExpect);
    }

    static void OnConnectFailure(void * context, const ScopedNodeId & peer, CHIP_ERROR err)
    {
        Pair * self = static_cast<Pair *>(context);
        Scope scope(*self);
        self->mConnecting = false;
        CTF_ERR("node 0x" ChipLogFormatX64 " unreachable: %" CHIP_ERROR_FORMAT, ChipLogValueX64(self->mNode),
                err.Format());
        self->mRelay.mStats.deviceConnectFailures++;
        self->FailCloud(Status::Failure);
        self->Finish();
    }

public:
    SubscriptionId mSubscriptionId = 0; // device-initiated reports

private:
    Relay & mRelay;
    const Origin mOrigin;
    const uint16_t mFwdLsid;
    const NodeId mNode;
    Messaging::ExchangeHolder mCloud;
    Messaging::ExchangeHolder mDev;
    Callback::Callback<OnDeviceConnected> mOnConnected;
    Callback::Callback<OnDeviceConnectionFailure> mOnFailure;

    System::PacketBufferHandle mPending;
    uint8_t mPendingType  = 0;
    bool mPendingExpect   = false;
    bool mConnecting      = false;
    bool mStarted         = false;
    bool mDone            = false;
    int mDepth            = 0;
    uint8_t mFirst        = 0;
    uint8_t mLastCloud    = 0;
    uint8_t mLastDev      = 0;
    bool mDevMore         = false;
    bool mWriteMore       = false;
    bool mPrimed          = false;
    uint8_t mRetries      = 0;
    static constexpr uint8_t kMaxRetries = 10;
    static constexpr uint32_t kRetryMs   = 200;
};

Relay & Relay::Instance()
{
    static Relay sRelay;
    return sRelay;
}

CHIP_ERROR Relay::Init(const Config & config)
{
    VerifyOrReturnError(config.controller != nullptr && config.controller->ExchangeMgr() != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    mConfig     = config;
    mController = config.controller;
    // Take the whole Interaction Model protocol from the engine (replacing its
    // registration); what isn't ours is handed back to it.
    return mController->ExchangeMgr()->RegisterUnsolicitedMessageHandlerForProtocol(Protocols::InteractionModel::Id, this);
}

ErrCode Relay::OpenSession(uint32_t conn, NodeId node, uint16_t cloudLsid, NodeId cloudNode,
                           const Transport::PeerAddress & bridge, const uint8_t connKey[kKeyLen], uint16_t & fwdLsid)
{
    VerifyOrReturnValue(mController != nullptr, kErrInternal);
    VerifyOrReturnValue(IsOperationalNodeId(node) && IsOperationalNodeId(cloudNode) && cloudLsid != 0, kErrBadNode);
    if (mConfig.nodeAllowed != nullptr && !mConfig.nodeAllowed(node))
    {
        CTF_ERR("conn %u: node 0x" ChipLogFormatX64 " is not one of this forwarder's nodes",
                static_cast<unsigned>(conn), ChipLogValueX64(node));
        return kErrPolicy;
    }
    CloudSession * slot = nullptr;
    for (auto & s : mSessions)
    {
        // A session CHIP released on its own (evicted from a full table):
        // free the slot and its subscriptions.
        if (s.inUse && !s.holder)
        {
            ReleaseSession(s);
        }
        if (!s.inUse && slot == nullptr)
        {
            slot = &s;
        }
    }
    VerifyOrReturnValue(slot != nullptr, kErrNoMemory);

    // The cloud's view: it talks to `node`, so the forwarder's end of the
    // session is `node` and the peer is the cloud controller.
    const FabricIndex fabric = mController->GetFabricIndex();
    SecretSession pairing;
    CHIP_ERROR err = pairing.Allocate(*mController->SessionMgr(), ScopedNodeId(node, fabric), ScopedNodeId(cloudNode, fabric),
                                      CryptoContext::SessionRole::kResponder);
    if (err == CHIP_NO_ERROR)
    {
        const uint16_t lsid = pairing.LocalId();
        uint8_t secret[kKeyLen];
        if (!SessionSecret(connKey, node, cloudLsid, lsid, secret))
        {
            pairing.Abandon();
            return kErrInternal;
        }
        const ReliableMessageProtocolConfig mrp{ System::Clock::Milliseconds32(kCloudMrpIntervalMs),
                                                 System::Clock::Milliseconds32(kCloudMrpIntervalMs) };
        err = pairing.Activate(cloudLsid, secret, bridge, mrp, slot->holder);
        memset(secret, 0, sizeof(secret));
        if (err == CHIP_NO_ERROR)
        {
            fwdLsid = lsid;
        }
    }
    if (err != CHIP_NO_ERROR)
    {
        CTF_ERR("session for node 0x" ChipLogFormatX64 " failed: %" CHIP_ERROR_FORMAT, ChipLogValueX64(node),
                err.Format());
        return err == CHIP_ERROR_NO_MEMORY ? kErrNoMemory : kErrInternal;
    }
    slot->inUse  = true;
    slot->conn   = conn;
    slot->node   = node;
    slot->fwdLsid = fwdLsid;
    mStats.sessionsOpened++;
    CTF_LOG("conn %u: session %u for node 0x" ChipLogFormatX64, static_cast<unsigned>(conn), fwdLsid,
                    ChipLogValueX64(node));
    return kErrNone;
}

void Relay::CloseSession(uint32_t conn, uint16_t fwdLsid)
{
    CloudSession * s = FindSession(fwdLsid);
    if (s != nullptr && s->conn == conn)
    {
        ReleaseSession(*s);
    }
}

void Relay::CloseConnection(uint32_t conn)
{
    for (auto & s : mSessions)
    {
        if (s.inUse && s.conn == conn)
        {
            ReleaseSession(s);
        }
    }
}

void Relay::ReleaseSession(CloudSession & s)
{
    for (auto & sub : mSubs)
    {
        if (sub.inUse && sub.fwdLsid == s.fwdLsid)
        {
            sub.inUse = false; // the node's next report gets InvalidSubscription from the engine
        }
    }
    if (s.holder)
    {
        s.holder->AsSecureSession()->MarkForEviction();
    }
    s.holder.Release();
    s.inUse = false;
}

Relay::CloudSession * Relay::FindSession(uint16_t fwdLsid)
{
    for (auto & s : mSessions)
    {
        if (s.inUse && s.fwdLsid == fwdLsid)
        {
            return &s;
        }
    }
    return nullptr;
}

void Relay::RecordSubscription(NodeId node, SubscriptionId id, uint16_t fwdLsid, uint16_t maxIntervalS)
{
    const System::Clock::Timestamp now = System::SystemClock().GetMonotonicTimestamp();
    Subscription * slot = nullptr;
    for (auto & sub : mSubs)
    {
        if (sub.inUse && sub.node == node && sub.id == id)
        {
            slot = &sub;
            break;
        }
        // Silent past two max intervals and a minute: the node ended it (it
        // restarted, or the cloud resubscribed) without a report saying so.
        if (sub.inUse && now - sub.lastSeen > System::Clock::Seconds32(2u * sub.maxIntervalS + 60u))
        {
            sub.inUse = false;
        }
        if (!sub.inUse && slot == nullptr)
        {
            slot = &sub;
        }
    }
    if (slot == nullptr)
    {
        CTF_ERR("subscription table full; reports for 0x%08x will be refused", static_cast<unsigned>(id));
        return;
    }
    slot->inUse        = true;
    slot->node         = node;
    slot->id           = id;
    slot->fwdLsid       = fwdLsid;
    slot->maxIntervalS = maxIntervalS;
    slot->lastSeen     = now;
}

void Relay::ForgetSubscription(NodeId node, SubscriptionId id)
{
    for (auto & sub : mSubs)
    {
        if (sub.inUse && sub.node == node && sub.id == id)
        {
            sub.inUse = false;
        }
    }
}

size_t Relay::SessionCount() const
{
    size_t n = 0;
    for (const auto & s : mSessions)
    {
        n += s.inUse && s.holder ? 1 : 0;
    }
    return n;
}

size_t Relay::SubscriptionCount() const
{
    size_t n = 0;
    for (const auto & sub : mSubs)
    {
        n += sub.inUse ? 1 : 0;
    }
    return n;
}

CHIP_ERROR Relay::OnUnsolicitedMessageReceived(const PayloadHeader & payloadHeader, const SessionHandle & session,
                                               Messaging::ExchangeDelegate *& newDelegate)
{
    auto * engine = app::InteractionModelEngine::GetInstance();
    if (session->IsSecureSession())
    {
        CloudSession * s = FindSession(session->AsSecureSession()->GetLocalSessionId());
        if (s != nullptr && s->holder && s->holder.Contains(session))
        {
            newDelegate = new (std::nothrow) Pair(*this, Pair::Origin::kCloud, s->fwdLsid, s->node);
            VerifyOrReturnError(newDelegate != nullptr, CHIP_ERROR_NO_MEMORY);
            mStats.exchangesFromCloud++;
            return CHIP_NO_ERROR;
        }
        if (payloadHeader.HasMessageType(MsgType::ReportData))
        {
            newDelegate = this; // decided once the subscription ID is known
            return CHIP_NO_ERROR;
        }
    }
    return static_cast<Messaging::UnsolicitedMessageHandler *>(engine)->OnUnsolicitedMessageReceived(payloadHeader, session, newDelegate);
}

void Relay::OnExchangeCreationFailed(Messaging::ExchangeDelegate * delegate)
{
    if (delegate != this && delegate != app::InteractionModelEngine::GetInstance())
    {
        delete static_cast<Pair *>(delegate);
    }
}

CHIP_ERROR Relay::OnMessageReceived(Messaging::ExchangeContext * ec, const PayloadHeader & payloadHeader,
                                    System::PacketBufferHandle && payload)
{
    auto * engine = app::InteractionModelEngine::GetInstance();
    const SessionHandle session = ec->GetSessionHandle();
    if (mController != nullptr && session->IsSecureSession() && session->GetFabricIndex() == mController->GetFabricIndex())
    {
        const NodeId node = session->AsSecureSession()->GetPeerNodeId();
        SubscriptionId id = 0;
        System::PacketBufferTLVReader reader;
        app::ReportDataMessage::Parser p;
        if (ParseMessage(payload, reader, p) == CHIP_NO_ERROR && p.GetSubscriptionId(&id) == CHIP_NO_ERROR)
        {
            for (auto & sub : mSubs)
            {
                if (sub.inUse && sub.node == node && sub.id == id)
                {
                    sub.lastSeen = System::SystemClock().GetMonotonicTimestamp();
                    Pair * pair  = new (std::nothrow) Pair(*this, Pair::Origin::kDevice, sub.fwdLsid, node);
                    if (pair == nullptr)
                    {
                        break;
                    }
                    pair->mSubscriptionId = id;
                    mStats.reportsFromDevice++;
                    ec->SetDelegate(pair);
                    return pair->OnMessageReceived(ec, payloadHeader, std::move(payload));
                }
            }
        }
    }
    mStats.reportsToEngine++;
    ec->SetDelegate(engine);
    return static_cast<Messaging::ExchangeDelegate *>(engine)->OnMessageReceived(ec, payloadHeader, std::move(payload));
}

} // namespace ctf
