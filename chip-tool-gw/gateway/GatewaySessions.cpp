// SPDX-License-Identifier: Apache-2.0

// Sessions to the gateway's nodes: CHIP's lookup hook, the session table, and
// the transport that carries their messages over the gateway stream; see
// GatewayClient.h.
#include "GatewayClient.h"
#include "mgw_session.h"

#include <arpa/inet.h>
#include <string.h>

#include <memory>
#include <vector>

#include <app/CASESessionManager.h>
#include <app/InteractionModelEngine.h>
#include <controller/CHIPDeviceControllerFactory.h>
#include <lib/support/logging/CHIPLogging.h>
#include <platform/CHIPDeviceLayer.h>
#include <transport/SessionManager.h>
#include <transport/TransportMgr.h>
#include <transport/raw/Base.h>

#include "GatewayStream.h"
#include "mgw_proto.h"

using namespace chip;

namespace GatewayClient {

namespace {

// Retransmission interval towards the gateway: the stream is reliable, but the
// relay's round trip can be several hundred milliseconds.
constexpr uint32_t kGatewayMrpIntervalMs = 2000;
constexpr size_t kMaxNodes               = 64; // the gateway's sessions per connection (the ESP32's)

struct Entry
{
    bool inUse         = false;
    NodeId node        = kUndefinedNodeId;
    FabricIndex fabric = kUndefinedFabricIndex;
    uint32_t epoch     = 0;
    uint16_t lsid      = 0;
    uint16_t gwLsid    = 0;
    uint32_t lastUse   = 0;
    SessionHolder holder;
};

uint32_t sUseClock = 0;

Entry sEntries[kMaxNodes];

GatewayStream & Stream()
{
    return GatewayStream::Instance();
}

void Drop(Entry & e)
{
    // The gateway's end too, while its connection lasts (even if CHIP already
    // released our end, e.g. evicted from a full table).
    if (Stream().Epoch() == e.epoch)
    {
        Stream().Close(e.lsid, e.gwLsid);
    }
    if (e.holder)
    {
        e.holder->AsSecureSession()->MarkForEviction();
    }
    e.holder.Release();
    e.inUse = false;
}

} // namespace

namespace {

bool sInEnsure = false;

// The peer address of every session to a gateway node. No socket has it: the
// transport below recognises it and hands the message to the stream.
Transport::PeerAddress GatewayPeer()
{
    in_addr a4;
    a4.s_addr = htonl(INADDR_LOOPBACK);
    return Transport::PeerAddress::UDP(Inet::IPAddress(a4), 1);
}

// In front of the stack's own transports: messages to GatewayPeer() go over
// the gateway stream, in-process (no UDP, which some sandboxes
// refuse even on loopback); everything else passes through unchanged.
class GatewayTransport : public Transport::Base
{
public:
    void SetInner(Transport::Base * inner) { mInner = inner; }

    CHIP_ERROR SendMessage(const Transport::PeerAddress & address, System::PacketBufferHandle && msg) override
    {
        if (address == GatewayPeer())
        {
            VerifyOrReturnError(!msg.IsNull() && !msg->HasChainedBuffer(), CHIP_ERROR_INVALID_ARGUMENT);
            return Stream().SendMatter(msg->Start(), msg->DataLength()) ? CHIP_NO_ERROR : CHIP_ERROR_CONNECTION_ABORTED;
        }
        return mInner->SendMessage(address, std::move(msg));
    }
    bool CanSendToPeer(const Transport::PeerAddress & address) override
    {
        return address == GatewayPeer() || mInner->CanSendToPeer(address);
    }
    bool CanListenMulticast() override { return mInner->CanListenMulticast(); }
    CHIP_ERROR MulticastGroupJoinLeave(const Transport::PeerAddress & address, bool join) override
    {
        return mInner->MulticastGroupJoinLeave(address, join);
    }
#if INET_CONFIG_ENABLE_TCP_ENDPOINT
    CHIP_ERROR TCPConnect(const Transport::PeerAddress & address, Transport::AppTCPConnectionCallbackCtxt * appState,
                          Transport::ActiveTCPConnectionHandle & outPeerConnHandle) override
    {
        return mInner->TCPConnect(address, appState, outPeerConnHandle);
    }
#endif
    // A message from the gateway, on the CHIP thread.
    void Deliver(System::PacketBufferHandle && msg) { HandleMessageReceived(GatewayPeer(), std::move(msg)); }

private:
    Transport::Base * mInner = nullptr;
};

GatewayTransport sTransport;
void * sTransportFor = nullptr; // the system state's transport manager it was put in front of

// Puts sTransport in front of the stack's transports (once per system state).
// TransportMgrBase::Close() only forgets the transport and session manager;
// the stack's transports stay open and keep delivering to the manager.
CHIP_ERROR EnsureTransport(const Controller::DeviceControllerSystemState * state)
{
    auto * tm = state->TransportMgr();
    VerifyOrReturnError(tm != nullptr, CHIP_ERROR_INCORRECT_STATE);
    if (sTransportFor == tm)
    {
        return CHIP_NO_ERROR;
    }
    TransportMgrDelegate * sessions = tm->GetSessionManager();
    sTransport.SetInner(&tm->GetTransport());
    TransportMgrBase * base = tm;
    base->TransportMgrBase::Close();
    ReturnErrorOnFailure(base->Init(&sTransport));
    base->SetSessionManager(sessions);
    sTransportFor = tm;
    return CHIP_NO_ERROR;
}

void DeliverInChipTask(intptr_t arg)
{
    std::unique_ptr<std::vector<uint8_t>> msg(reinterpret_cast<std::vector<uint8_t> *>(arg));
    System::PacketBufferHandle buf = System::PacketBufferHandle::NewWithData(msg->data(), msg->size());
    if (!buf.IsNull() && sTransportFor != nullptr)
    {
        sTransport.Deliver(std::move(buf));
    }
}

// On the stream's reader thread: copy, and deliver on the CHIP thread.
void OnMatter(const uint8_t * b, size_t n)
{
    auto * msg = new (std::nothrow) std::vector<uint8_t>(b, b + n);
    if (msg != nullptr &&
        DeviceLayer::PlatformMgr().ScheduleWork(DeliverInChipTask, reinterpret_cast<intptr_t>(msg)) != CHIP_NO_ERROR)
    {
        delete msg;
    }
}

CHIP_ERROR LookupHook(const ScopedNodeId & peer)
{
    return Ensure(peer.GetFabricIndex(), peer.GetNodeId());
}

// A sleepy device checked in with the gateway (its ICD client): the device
// sends one only when that client has no live subscription, and every cloud
// subscription reaches it as the gateway's. So ours to that node are gone:
// resubscribe now, while it listens (as for a Check-In on our own fabric).
void ActiveInChipTask(intptr_t arg)
{
    const NodeId node = static_cast<NodeId>(arg);
    auto * state      = Controller::DeviceControllerFactory::GetInstance().GetSystemState();
    VerifyOrReturn(state != nullptr && state->Fabrics() != nullptr);
    ChipLogProgress(chipTool, "Gateway: node 0x" ChipLogFormatX64 " checked in (sleepy device awake)", ChipLogValueX64(node));
    for (const auto & fabric : *state->Fabrics())
    {
        app::InteractionModelEngine::GetInstance()->OnActiveModeNotification(ScopedNodeId(node, fabric.GetFabricIndex()),
                                                                             fabric.GetNodeId());
    }
}

void OnEvent(uint8_t kind, uint64_t node)
{
    static_assert(sizeof(intptr_t) >= sizeof(NodeId), "node IDs travel as intptr_t");
    VerifyOrReturn(kind == mgw::kEventIcdActive);
    TEMPORARY_RETURN_IGNORED DeviceLayer::PlatformMgr().ScheduleWork(ActiveInChipTask, static_cast<intptr_t>(node));
}

} // namespace

void Install()
{
    VerifyOrReturn(Enabled());
    // Every CASESessionManager in the process (patches/0001-*.patch).
    CASESessionManager::SetSessionLookupHook(LookupHook);
    Stream().SetEventHandler(OnEvent);
    Stream().SetMatterHandler(OnMatter);
}

CHIP_ERROR Ensure(FabricIndex fabric, NodeId node)
{
    VerifyOrReturnError(Enabled(), CHIP_NO_ERROR);
    // A lookup started from inside this one (evicting a session can resubscribe):
    // fail it rather than let CHIP run CASE without the gateway; it retries.
    VerifyOrReturnError(!sInEnsure, CHIP_ERROR_BUSY);
    auto * state = Controller::DeviceControllerFactory::GetInstance().GetSystemState();
    VerifyOrReturnError(state != nullptr && state->SessionMgr() != nullptr && state->Fabrics() != nullptr,
                        CHIP_ERROR_INCORRECT_STATE);
    const FabricInfo * info = state->Fabrics()->FindFabricWithIndex(fabric);
    VerifyOrReturnError(info != nullptr, CHIP_ERROR_INVALID_FABRIC_INDEX);
    const NodeId self = info->GetNodeId();

    sInEnsure            = true; // evicting a session can start a lookup (resubscription)
    const uint32_t epoch = Stream().Epoch();
    Entry * slot         = nullptr;
    for (auto & e : sEntries)
    {
        if (e.inUse && e.node == node && e.fabric == fabric)
        {
            if (e.holder && e.epoch == epoch && epoch != 0 && e.holder->AsSecureSession()->IsActiveSession() &&
                !e.holder->AsSecureSession()->IsDefunct())
            {
                e.lastUse = ++sUseClock;
                sInEnsure = false;
                return CHIP_NO_ERROR;
            }
            Drop(e); // the stream (and the gateway's end) went away, or the session was given up
        }
    }
    for (auto & e : sEntries)
    {
        if (!e.inUse)
        {
            slot = &e;
            break;
        }
    }
    if (slot == nullptr)
    {
        // Full: give up the least recently used node's session (and the
        // subscriptions on it).
        slot = &sEntries[0];
        for (auto & e : sEntries)
        {
            if (e.lastUse < slot->lastUse)
            {
                slot = &e;
            }
        }
        ChipLogError(chipTool, "Gateway: %u nodes in use, dropping node 0x" ChipLogFormatX64,
                     static_cast<unsigned>(kMaxNodes), ChipLogValueX64(slot->node));
        Drop(*slot);
    }
    sInEnsure = false;

    ReturnErrorOnFailure(EnsureTransport(state));
    // The gateway's end is `node`; ours is this controller (initiator).
    mgw::SecretSession pairing;
    ReturnErrorOnFailure(pairing.Allocate(*state->SessionMgr(), ScopedNodeId(self, fabric), ScopedNodeId(node, fabric),
                                          CryptoContext::SessionRole::kInitiator));
    const uint16_t lsid = pairing.LocalId();
    uint16_t gwLsid = 0, code = 0;
    uint32_t keyEpoch = 0;
    uint8_t secret[mgw::kKeyLen];
    GatewayStream::Result r = Stream().Open(node, lsid, self, gwLsid, secret, code, keyEpoch);
    if (r != GatewayStream::Result::kOk)
    {
        pairing.Abandon();
        const std::string why = r == GatewayStream::Result::kRefused ? mgw::ErrName(code) : Stream().LastError();
        ChipLogError(chipTool, "Gateway: no session for node 0x" ChipLogFormatX64 " (%s)", ChipLogValueX64(node), why.c_str());
        NoteFailure("no session for node " + std::to_string(node) + ": " + why,
                    r != GatewayStream::Result::kRefused ? Stream().LastFailure()
                        : code == mgw::kErrPolicy        ? GatewayStream::Failure::kPolicy
                                                         : GatewayStream::Failure::kOther);
        return r == GatewayStream::Result::kRefused ? CHIP_ERROR_NOT_FOUND : CHIP_ERROR_CONNECTION_ABORTED;
    }

    const ReliableMessageProtocolConfig mrp{ System::Clock::Milliseconds32(kGatewayMrpIntervalMs),
                                             System::Clock::Milliseconds32(kGatewayMrpIntervalMs) };
    CHIP_ERROR err = pairing.Activate(gwLsid, secret, GatewayPeer(), mrp, slot->holder);
    memset(secret, 0, sizeof(secret));
    if (err != CHIP_NO_ERROR)
    {
        if (Stream().Epoch() == keyEpoch)
        {
            Stream().Close(lsid, gwLsid); // the gateway's end, opened for nothing
        }
        return err;
    }

    slot->inUse  = true;
    slot->node   = node;
    slot->fabric = fabric;
    slot->epoch  = keyEpoch;
    slot->lsid   = lsid;
    slot->gwLsid = gwLsid;
    slot->lastUse = ++sUseClock;
    ChipLogProgress(chipTool, "Gateway: session %u (gateway %u) for node 0x" ChipLogFormatX64, lsid, gwLsid,
                    ChipLogValueX64(node));
    return CHIP_NO_ERROR;
}

} // namespace GatewayClient
