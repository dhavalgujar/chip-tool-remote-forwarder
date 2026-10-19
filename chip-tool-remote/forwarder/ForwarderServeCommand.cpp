// SPDX-License-Identifier: Apache-2.0

#include "ForwarderServeCommand.h"

#include <stdlib.h>
#include <string.h>

#include <string>

#include <thread>

#include <controller/CHIPDeviceControllerFactory.h>
#include <platform/CHIPDeviceLayer.h>

#include "ForwarderConnectFile.h"
#include "ctf_relay.h"
#include "ctf_server.h"

namespace {

bool SpawnThread(void (*fn)(void *), void * arg, const char * name, size_t stack)
{
    std::thread(fn, arg).detach();
    return true;
}

uint32_t sStatsInterval = 60;

// The port of a host:port (or [v6]:port) endpoint; 0 if there is none.
uint16_t EndpointPort(const std::string & endpoint)
{
    size_t colon = endpoint.rfind(':');
    if (colon == std::string::npos || colon + 1 == endpoint.size())
        return 0;
    char * end    = nullptr;
    unsigned long p = strtoul(endpoint.c_str() + colon + 1, &end, 10);
    return (*end == '\0' && p > 0 && p <= UINT16_MAX) ? static_cast<uint16_t>(p) : 0;
}

} // namespace

void ForwarderServeCommand::LogStats(chip::System::Layer * layer, void * context)
{
    auto & r = ctf::Relay::Instance();
    ctf::RelayStats s   = r.Stats();
    ctf::ServerStats ss = ctf::GetServerStats();
    ChipLogProgress(chipTool,
                    "ctf stats: conns %u active %u authfail %u | sessions %u subs %u pairs %u | from-cloud %u to-node %u "
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

CHIP_ERROR ForwarderServeCommand::RunCommand()
{
    ctf::ServerConfig sc;
    std::string endpoint, why;
    if (!ForwarderClient::ReadConnectFile(mConnectFile, "the connect file", endpoint, sc.secret, sizeof(sc.secret), sc.secretLen,
                                        why))
    {
        memset(sc.secret, 0, sizeof(sc.secret));
        ChipLogError(chipTool, "forwarder serve: %s", why.c_str());
        return CHIP_ERROR_INVALID_ARGUMENT;
    }
    sc.port = EndpointPort(endpoint);
    VerifyOrReturnError(sc.port != 0, CHIP_ERROR_INVALID_ARGUMENT,
                        ChipLogError(chipTool, "forwarder serve: the connect file's endpoint must be host:port"));

    auto * state = chip::Controller::DeviceControllerFactory::GetInstance().GetSystemState();
    VerifyOrReturnError(state != nullptr && state->TransportMgr() != nullptr, CHIP_ERROR_INCORRECT_STATE);
    // DeviceTransportMgr: [0] UDP over IPv6, [1] UDP over IPv4 (same port).
    sc.chipUdpPort = state->TransportMgr()->GetTransport().GetImplAtIndex<1>().GetBoundPort();
    sc.spawn       = SpawnThread;

    ctf::Relay::Config rc;
    rc.controller = &CurrentCommissioner();
    ReturnErrorOnFailure(ctf::Relay::Instance().Init(rc));
    bool started = ctf::StartServer(sc);
    memset(sc.secret, 0, sizeof(sc.secret));
    VerifyOrReturnError(started, CHIP_ERROR_INTERNAL);
    ChipLogProgress(chipTool, "forwarder serve: fabric index %u, controller node 0x" ChipLogFormatX64 ", TCP %u",
                    CurrentCommissioner().GetFabricIndex(), ChipLogValueX64(CurrentCommissioner().GetNodeId()), sc.port);

    sStatsInterval = mStatsInterval.ValueOr(60);
    if (sStatsInterval > 0)
    {
        TEMPORARY_RETURN_IGNORED chip::DeviceLayer::SystemLayer().StartTimer(chip::System::Clock::Seconds32(sStatsInterval),
                                                                             LogStats, this);
    }
    return CHIP_NO_ERROR; // runs until killed
}

void registerCommandsForwarderServe(Commands & commands, CredentialIssuerCommands * credsIssuerConfig)
{
    commands_list clusterCommands = {
        make_unique<ForwarderServeCommand>(credsIssuerConfig),
    };
    commands.RegisterCommandSet("Forwarder", clusterCommands, "A forwarder relay on this host (tests).");
}
