// SPDX-License-Identifier: Apache-2.0

/*
 * Matter gateway relay. Ends a secure session from a cloud
 * controller (keyed from a shared secret, see mgw_session.h) for each node
 * the controller talks to, and relays every Interaction Model exchange on it
 * onto the gateway's own CASE session with that node. Subscription reports
 * the node sends later are relayed back on the session that subscribed.
 *
 * The relay reads only what it needs to know when an exchange ends (message
 * type, SuppressResponse, MoreChunkedMessages, subscription IDs, a status) and
 * forces KeepSubscriptions on subscribe requests (every cloud client shares the
 * gateway's identity on the node). Payloads are otherwise passed through.
 *
 * Everything here runs on the CHIP thread.
 */
#pragma once

#include "mgw_session.h"

#include <controller/CHIPDeviceController.h>
#include <lib/core/DataModelTypes.h>
#include <messaging/ExchangeDelegate.h>
#include <transport/Session.h>
#include <transport/raw/PeerAddress.h>

#include "mgw_proto.h"

namespace mgw {

struct RelayStats
{
    uint32_t sessionsOpened;
    uint32_t exchangesFromCloud;
    uint32_t reportsFromDevice;
    uint32_t reportsToEngine;
    uint32_t messagesToDevice;
    uint32_t messagesToCloud;
    uint32_t deviceConnectFailures;
    uint32_t timeouts;
    uint32_t sendFailures;
};

class Pair;

class Relay : public chip::Messaging::UnsolicitedMessageHandler, public chip::Messaging::ExchangeDelegate
{
public:
    struct Config
    {
        chip::Controller::DeviceController * controller = nullptr;
        // Which nodes a cloud controller may open sessions to (null: any).
        bool (*nodeAllowed)(chip::NodeId node) = nullptr;
    };

    static Relay & Instance();

    CHIP_ERROR Init(const Config & config);
    bool IsReady() const { return mController != nullptr; }

    // A session for `node`, owned by stream connection `conn`. On success
    // gwLsid is the gateway's session ID for it.
    ErrCode OpenSession(uint32_t conn, chip::NodeId node, uint16_t cloudLsid, chip::NodeId cloudNode,
                        const chip::Transport::PeerAddress & bridge, const uint8_t connKey[kKeyLen], uint16_t & gwLsid);
    void CloseSession(uint32_t conn, uint16_t gwLsid);
    void CloseConnection(uint32_t conn);

    RelayStats Stats() const { return mStats; }
    size_t SessionCount() const;
    size_t SubscriptionCount() const;
    size_t PairCount() const { return mPairs; }

    // UnsolicitedMessageHandler: every Interaction Model message that starts an exchange.
    CHIP_ERROR OnUnsolicitedMessageReceived(const chip::PayloadHeader & payloadHeader, const chip::SessionHandle & session,
                                            chip::Messaging::ExchangeDelegate *& newDelegate) override;
    void OnExchangeCreationFailed(chip::Messaging::ExchangeDelegate * delegate) override;

    // ExchangeDelegate: a ReportData on a node's session, before it is known
    // whether a cloud client subscribed to it.
    CHIP_ERROR OnMessageReceived(chip::Messaging::ExchangeContext * ec, const chip::PayloadHeader & payloadHeader,
                                 chip::System::PacketBufferHandle && payload) override;
    void OnResponseTimeout(chip::Messaging::ExchangeContext * ec) override {}

private:
    friend class Pair;

    // Below CHIP's session pool (CHIPProjectConfig.h, 128), which the
    // gateway's own CASE sessions with the nodes share: past it CHIP evicts
    // sessions on its own.
    static constexpr size_t kMaxSessions = 64;
    static constexpr size_t kMaxSubscriptions = 128;
    // Retransmission interval for messages to the cloud (MRP over a stream
    // with a relay's round trip).
    static constexpr uint32_t kCloudMrpIntervalMs = 2000;
    // How long one side may take to answer before the pair is dropped.
    static constexpr uint32_t kResponseTimeoutMs = 30000;

    struct CloudSession
    {
        bool inUse = false;
        uint32_t conn = 0;
        chip::NodeId node = chip::kUndefinedNodeId;
        uint16_t gwLsid = 0;
        StayingSessionHolder holder; // mgw_session.h
    };
    struct Subscription
    {
        bool inUse = false;
        chip::NodeId node = chip::kUndefinedNodeId;
        chip::SubscriptionId id = 0;
        uint16_t gwLsid = 0;
        uint16_t maxIntervalS = 0;
        chip::System::Clock::Timestamp lastSeen;
    };

    CloudSession * FindSession(uint16_t gwLsid);
    void ReleaseSession(CloudSession & s);
    void RecordSubscription(chip::NodeId node, chip::SubscriptionId id, uint16_t gwLsid, uint16_t maxIntervalS);
    void ForgetSubscription(chip::NodeId node, chip::SubscriptionId id);

    chip::Controller::DeviceController * mController = nullptr;
    Config mConfig;
    CloudSession mSessions[kMaxSessions];
    Subscription mSubs[kMaxSubscriptions];
    RelayStats mStats = {};
    size_t mPairs = 0;
};

} // namespace mgw
