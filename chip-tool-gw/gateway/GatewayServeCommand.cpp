// SPDX-License-Identifier: Apache-2.0

#include "GatewayServeCommand.h"

#include <string.h>

#include <thread>

#include <controller/CHIPDeviceControllerFactory.h>
#include <platform/CHIPDeviceLayer.h>

#include "GatewaySecretFile.h"
#include "mgw_relay.h"
#include "mgw_server.h"

namespace {

bool SpawnThread(void (*fn)(void *), void * arg, const char * name, size_t stack)
{
    std::thread(fn, arg).detach();
    return true;
}

uint32_t sStatsInterval = 60;

} // namespace

void GatewayServeCommand::LogStats(chip::System::Layer * layer, void * context)
{
    auto & r = mgw::Relay::Instance();
    mgw::RelayStats s   = r.Stats();
    mgw::ServerStats ss = mgw::GetServerStats();
    ChipLogProgress(chipTool,
                    "mgw stats: conns %u active %u authfail %u | sessions %u subs %u pairs %u | from-cloud %u to-node %u "
                    "to-cloud %u reports %u (engine %u) | connfail %u timeouts %u sendfail %u",
                    static_cast<unsigned>(ss.accepted), static_cast<unsigned>(ss.active), static_cast<unsigned>(ss.authFailures),
                    static_cast<unsigned>(r.SessionCount()), static_cast<unsigned>(r.SubscriptionCount()),
                    static_cast<unsigned>(r.PairCount()), static_cast<unsigned>(s.exchangesFromCloud),
                    static_cast<unsigned>(s.messagesToDevice), static_cast<unsigned>(s.messagesToCloud),
                    static_cast<unsigned>(s.reportsFromDevice), static_cast<unsigned>(s.reportsToEngine),
                    static_cast<unsigned>(s.deviceConnectFailures), static_cast<unsigned>(s.timeouts),
                    static_cast<unsigned>(s.sendFailures));
    if (sStatsInterval > 0)
    {
        TEMPORARY_RETURN_IGNORED layer->StartTimer(chip::System::Clock::Seconds32(sStatsInterval), LogStats, context);
    }
}

CHIP_ERROR GatewayServeCommand::RunCommand()
{
    mgw::ServerConfig sc;
    sc.secretLen = GatewayClient::ReadSecretFile(mSecretFile, sc.secret, sizeof(sc.secret));
    VerifyOrReturnError(sc.secretLen >= mgw::kMinSecretLen, CHIP_ERROR_INVALID_ARGUMENT,
                        ChipLogError(chipTool, "gateway serve: the secret must be 32-128 hex digits or 16-64 raw bytes"));

    auto * state = chip::Controller::DeviceControllerFactory::GetInstance().GetSystemState();
    VerifyOrReturnError(state != nullptr && state->TransportMgr() != nullptr, CHIP_ERROR_INCORRECT_STATE);
    // DeviceTransportMgr: [0] UDP over IPv6, [1] UDP over IPv4 (same port).
    sc.chipUdpPort = state->TransportMgr()->GetTransport().GetImplAtIndex<1>().GetBoundPort();
    sc.port        = mTcpPort.ValueOr(mgw::kDefaultPort);
    sc.spawn       = SpawnThread;

    mgw::Relay::Config rc;
    rc.controller = &CurrentCommissioner();
    ReturnErrorOnFailure(mgw::Relay::Instance().Init(rc));
    bool started = mgw::StartServer(sc);
    memset(sc.secret, 0, sizeof(sc.secret));
    VerifyOrReturnError(started, CHIP_ERROR_INTERNAL);
    ChipLogProgress(chipTool, "gateway serve: fabric index %u, controller node 0x" ChipLogFormatX64 ", TCP %u",
                    CurrentCommissioner().GetFabricIndex(), ChipLogValueX64(CurrentCommissioner().GetNodeId()), sc.port);

    sStatsInterval = mStatsInterval.ValueOr(60);
    if (sStatsInterval > 0)
    {
        TEMPORARY_RETURN_IGNORED chip::DeviceLayer::SystemLayer().StartTimer(chip::System::Clock::Seconds32(sStatsInterval),
                                                                             LogStats, this);
    }
    return CHIP_NO_ERROR; // runs until killed
}

void registerCommandsGatewayServe(Commands & commands, CredentialIssuerCommands * credsIssuerConfig)
{
    commands_list clusterCommands = {
        make_unique<GatewayServeCommand>(credsIssuerConfig),
    };
    commands.RegisterCommandSet("Gateway", clusterCommands, "A Matter gateway relay on this host (tests).");
}
