// SPDX-License-Identifier: Apache-2.0

// forwarder-host: a forwarder relay on a host (tests): commission
// devices with the pairing commands, then "forwarder serve" relays cloud
// controllers' sessions to them.

#include "commands/common/Commands.h"
#include "commands/example/ExampleCredentialIssuerCommands.h"

#include "commands/delay/Commands.h"
#include "commands/discover/Commands.h"
#include "commands/icd/ICDCommand.h"
#include "commands/interactive/Commands.h"
#include "commands/pairing/Commands.h"
#include "commands/payload/Commands.h"
#include "commands/storage/Commands.h"

#include <zap-generated/cluster/Commands.h>

#include "ForwarderServeCommand.h"

int main(int argc, char * argv[])
{
    ExampleCredentialIssuerCommands credIssuerCommands;
    Commands commands;
    registerCommandsDelay(commands, &credIssuerCommands);
    registerCommandsDiscover(commands, &credIssuerCommands);
    registerCommandsICD(commands, &credIssuerCommands); // also CHIPCommand's Check-In delegate
    registerCommandsInteractive(commands, &credIssuerCommands);
    registerCommandsPayload(commands);
    registerCommandsPairing(commands, &credIssuerCommands);
    registerClusters(commands, &credIssuerCommands);
    registerCommandsStorage(commands);
    registerCommandsForwarderServe(commands, &credIssuerCommands);
    return commands.Run(argc, argv);
}
