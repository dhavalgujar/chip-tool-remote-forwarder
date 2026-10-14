// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "commands/common/CHIPCommand.h"
#include "commands/common/Commands.h"

/*
 * gateway call NAME [--params JSON]: run one of the gateway's own commands
 * (gateway mode), e.g. commissioning, which stays on the gateway:
 *   chip-tool gateway call matter.commission --params '{"code":"MT:..."}' --storage-directory DIR
 *   chip-tool gateway call matter.nodes --storage-directory DIR
 * Prints the result JSON; exit status 0 when it is {"ok":true,...}. While the
 * call runs (only then), this controller's fabric CA (the storage directory's)
 * signs what the gateway asks: the gateway's own certificate during
 * matter.enroll, and devices it commissions once it is enrolled.
 */
class GatewayCallCommand : public CHIPCommand
{
public:
    GatewayCallCommand(CredentialIssuerCommands * credsIssuerConfig) :
        CHIPCommand("call", credsIssuerConfig, "Run a command of the gateway (matter.commission, matter.nodes, matter.enroll, ...).")
    {
        AddArgument("name", &mName, "The gateway command, e.g. matter.commission.");
        AddArgument("params", &mParams, "Its parameters, a JSON object (default {}).");
        AddArgument("call-timeout", 0, 3600, &mTimeout, "Seconds to wait for the result (default 330).");
    }
    CHIP_ERROR RunCommand() override;
    chip::System::Clock::Timeout GetWaitDuration() const override
    {
        // the call's own timeout, plus connecting first (dial, proxy and TLS:
        // up to 50 s) and a margin
        return chip::System::Clock::Seconds16(static_cast<uint16_t>(mTimeout.ValueOr(330) + 50 + 15));
    }

private:
    static void Done(intptr_t self);

    char * mName = nullptr;
    chip::Optional<char *> mParams;
    chip::Optional<uint16_t> mTimeout;
    CHIP_ERROR mResult = CHIP_NO_ERROR;
    uint32_t mRun      = 0; // which run Done belongs to
};

void registerCommandsGateway(Commands & commands, CredentialIssuerCommands * credsIssuerConfig);
