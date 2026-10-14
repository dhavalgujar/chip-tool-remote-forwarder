// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "commands/common/CHIPCommand.h"
#include "commands/common/Commands.h"

/*
 * gateway serve: run a Matter gateway relay on this host (the same
 * relay core as the ESP32's, ../core). Cloud controllers in gateway mode
 * connect over TCP and reach the nodes this controller commissioned.
 */
class GatewayServeCommand : public CHIPCommand
{
public:
    GatewayServeCommand(CredentialIssuerCommands * credsIssuerConfig) :
        CHIPCommand("serve", credsIssuerConfig, "Relay Matter sessions from cloud controllers to this controller's nodes.")
    {
        AddArgument("secret-file", &mSecretFile, "The per-gateway secret: 32+ hex digits or 16-64 raw bytes.");
        AddArgument("tcp-port", 0, UINT16_MAX, &mTcpPort, "TCP port for cloud controllers (default 7401).");
        AddArgument("stats-interval", 0, UINT16_MAX, &mStatsInterval, "Seconds between stats lines (default 60, 0: off).");
    }

    CHIP_ERROR RunCommand() override;
    chip::System::Clock::Timeout GetWaitDuration() const override { return chip::System::Clock::Seconds32(7 * 24 * 3600); }

private:
    static void LogStats(chip::System::Layer * layer, void * context);

    char * mSecretFile = nullptr;
    chip::Optional<uint16_t> mTcpPort;
    chip::Optional<uint16_t> mStatsInterval;
};

void registerCommandsGatewayServe(Commands & commands, CredentialIssuerCommands * credsIssuerConfig);
