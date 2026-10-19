/*
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

// chip-tool-remote: upstream chip-tool's commands, with every node reached through
// the forwarder when CHIP_TOOL_REMOTE_CONNECT_FILE or CHIP_TOOL_REMOTE_TARGET is set
// (see forwarder/ForwarderStream.h).

#include "commands/common/Commands.h"
#include "commands/example/ExampleCredentialIssuerCommands.h"

#include "commands/clusters/SubscriptionsCommands.h"
#include "commands/dcl/Commands.h"
#include "commands/delay/Commands.h"
#include "commands/discover/Commands.h"
#include "commands/group/Commands.h"
#include "commands/icd/ICDCommand.h"
#include "commands/interactive/Commands.h"
#include "commands/pairing/Commands.h"
#include "commands/payload/Commands.h"
#include "commands/session-management/Commands.h"
#include "commands/storage/Commands.h"

#include <zap-generated/cluster/Commands.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#include "ForwarderClient.h"
#include "ForwarderCommands.h"
#include "ForwarderStream.h"

int main(int argc, char * argv[])
{
    ExampleCredentialIssuerCommands credIssuerCommands;
    Commands commands;
    if (!ForwarderClient::Enabled())
    {
        // Through the forwarder these can't work (discovery, PASE, the DCL,
        // groupcast from this machine): the forwarder's own commands do it
        // (forwarder call matter.commission, matter.nodes, ...).
        registerCommandsDCL(commands);
        registerCommandsDiscover(commands, &credIssuerCommands);
        registerCommandsPairing(commands, &credIssuerCommands);
        registerCommandsGroup(commands, &credIssuerCommands);
    }
    registerCommandsDelay(commands, &credIssuerCommands);
    registerCommandsICD(commands, &credIssuerCommands);
    registerCommandsInteractive(commands, &credIssuerCommands);
    registerCommandsPayload(commands);
    registerClusters(commands, &credIssuerCommands);
    registerCommandsSubscriptions(commands, &credIssuerCommands);
    registerCommandsStorage(commands);
    registerCommandsSessionManagement(commands, &credIssuerCommands);
    registerCommandsForwarder(commands, &credIssuerCommands);

    // Before any command starts the stack: sessions come from the forwarder.
    ForwarderClient::Install();
    // Asked for a forwarder but can't use it: stop, rather than run as plain
    // chip-tool (discovery and CASE of its own) behind the user's back.
    if ((getenv("CHIP_TOOL_REMOTE_TARGET") != nullptr || getenv("CHIP_TOOL_REMOTE_CONNECT_FILE") != nullptr) &&
        !ForwarderClient::Enabled())
    {
        fprintf(stderr, "chip-tool-remote: forwarder: %s\n", ForwarderClient::ForwarderStream::Instance().LastError().c_str());
        return 2;
    }

    // With a forwarder, this controller is reached by no device: its node ID
    // on the fabric can be the forwarder's own (both default to 112233), so
    // `interactive start` must not advertise it (upstream advertises by
    // default) or devices' Check-Ins and CASE could come here.
    std::vector<char *> args(argv, argv + argc);
    static char kAdvertise[] = "--advertise-operational";
    static char kNo[]        = "0";
    if (ForwarderClient::Enabled() && argc >= 3 && strcmp(argv[1], "interactive") == 0 &&
        strcmp(argv[2], "start") == 0)
    {
        bool given = false;
        for (int i = 3; i < argc; i++)
        {
            given = given || strcmp(argv[i], kAdvertise) == 0;
        }
        if (!given)
        {
            args.push_back(kAdvertise);
            args.push_back(kNo);
        }
    }
    int rc = commands.Run(static_cast<int>(args.size()), args.data());
    // CHIP's error says only "Connection aborted": say why, last.
    const std::string failure = ForwarderClient::LastFailure();
    if (rc != 0 && !failure.empty())
    {
        fprintf(stderr, "chip-tool-remote: forwarder: %s\n", failure.c_str());
    }
    return rc;
}
