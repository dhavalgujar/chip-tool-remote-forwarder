// SPDX-License-Identifier: Apache-2.0

#include "GatewayCommands.h"

#include <stdio.h>
#include <string.h>

#include <memory>
#include <thread>

#include <json/json.h>
#include <platform/CHIPDeviceLayer.h>

#include "GatewayClient.h"
#include "GatewayStream.h"

using GatewayClient::GatewayStream;

namespace {
struct DoneArgs
{
    GatewayCallCommand * cmd;
    uint32_t run;
};

// The gateway's answer: {"ok":true,"payload":...} or {"ok":false,"error":...}.
bool ResultOk(const std::string & json)
{
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value v;
    return reader->parse(json.data(), json.data() + json.size(), &v, nullptr) && v.isObject() && v["ok"].isBool() &&
        v["ok"].asBool();
}
} // namespace

void GatewayCallCommand::Done(intptr_t arg)
{
    auto * a = reinterpret_cast<DoneArgs *>(arg);
    GatewayCallCommand * c = a->cmd;
    // A run that CHIP already timed out: interactive mode reuses this command
    // object, and its answer must not end the next run.
    if (a->run == c->mRun)
    {
        GatewayClient::SetSigner(nullptr, false);
        c->SetCommandExitStatus(c->mResult);
    }
    delete a;
}

CHIP_ERROR GatewayCallCommand::RunCommand()
{
    VerifyOrReturnError(GatewayClient::Enabled(), CHIP_ERROR_INCORRECT_STATE,
                        ChipLogError(chipTool, "gateway call: set MATTER_GW_CONNECT_FILE"));
    // This command's fabric CA signs what the gateway asks while the call runs;
    // the gateway's own (controller) certificate only for matter.enroll.
    GatewayClient::SetSigner(&CurrentCommissioner(), strcmp(mName, "matter.enroll") == 0);
    const uint32_t run = ++mRun;
    // Off the CHIP thread, which stays free to sign.
    std::thread([this, run] {
        std::string out;
        GatewayStream::Result r =
            GatewayStream::Instance().Call(mName, mParams.ValueOr(const_cast<char *>("{}")), mTimeout.ValueOr(330), out);
        if (r == GatewayStream::Result::kOk)
        {
            printf("%s\n", out.c_str());
            fflush(stdout);
            mResult = ResultOk(out) ? CHIP_NO_ERROR : CHIP_ERROR_INTERNAL;
        }
        else
        {
            ChipLogError(chipTool, "gateway call %s: %s", mName, GatewayStream::Instance().LastError().c_str());
            GatewayClient::NoteFailure(std::string("gateway call ") + mName + ": " + GatewayStream::Instance().LastError(),
                                       GatewayStream::Instance().LastFailure());
            mResult = CHIP_ERROR_CONNECTION_ABORTED;
        }
        auto * args = new DoneArgs{ this, run };
        if (chip::DeviceLayer::PlatformMgr().ScheduleWork(Done, reinterpret_cast<intptr_t>(args)) != CHIP_NO_ERROR)
        {
            delete args;
        }
    }).detach();
    return CHIP_NO_ERROR;
}

void registerCommandsGateway(Commands & commands, CredentialIssuerCommands * credsIssuerConfig)
{
    commands_list clusterCommands = {
        make_unique<GatewayCallCommand>(credsIssuerConfig),
    };
    commands.RegisterCommandSet("Gateway", clusterCommands, "The Matter gateway's own commands.");
}
