// SPDX-License-Identifier: Apache-2.0

#include "ForwarderCommands.h"

#include <stdio.h>
#include <string.h>

#include <memory>
#include <thread>

#include <json/json.h>
#include <platform/CHIPDeviceLayer.h>

#include "ForwarderClient.h"
#include "ForwarderStream.h"

using ForwarderClient::ForwarderStream;

namespace {
struct DoneArgs
{
    ForwarderCallCommand * cmd;
    uint32_t run;
};

// The forwarder's answer: {"ok":true,"payload":...} or {"ok":false,"error":...}.
bool ResultOk(const std::string & json)
{
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value v;
    return reader->parse(json.data(), json.data() + json.size(), &v, nullptr) && v.isObject() && v["ok"].isBool() &&
        v["ok"].asBool();
}
} // namespace

void ForwarderCallCommand::Done(intptr_t arg)
{
    auto * a = reinterpret_cast<DoneArgs *>(arg);
    ForwarderCallCommand * c = a->cmd;
    // A run that CHIP already timed out: interactive mode reuses this command
    // object, and its answer must not end the next run.
    if (a->run == c->mRun)
    {
        ForwarderClient::SetSigner(nullptr, false);
        c->SetCommandExitStatus(c->mResult);
    }
    delete a;
}

CHIP_ERROR ForwarderCallCommand::RunCommand()
{
    VerifyOrReturnError(ForwarderClient::Enabled(), CHIP_ERROR_INCORRECT_STATE,
                        ChipLogError(chipTool, "forwarder call: set CHIP_TOOL_REMOTE_CONNECT_FILE"));
    // This command's fabric CA signs what the forwarder asks while the call runs;
    // the forwarder's own (controller) certificate only for matter.enroll.
    ForwarderClient::SetSigner(&CurrentCommissioner(), strcmp(mName, "matter.enroll") == 0);
    const uint32_t run = ++mRun;
    // Off the CHIP thread, which stays free to sign.
    std::thread([this, run] {
        std::string out;
        ForwarderStream::Result r =
            ForwarderStream::Instance().Call(mName, mParams.ValueOr(const_cast<char *>("{}")), mTimeout.ValueOr(330), out);
        if (r == ForwarderStream::Result::kOk)
        {
            printf("%s\n", out.c_str());
            fflush(stdout);
            mResult = ResultOk(out) ? CHIP_NO_ERROR : CHIP_ERROR_INTERNAL;
        }
        else
        {
            ChipLogError(chipTool, "forwarder call %s: %s", mName, ForwarderStream::Instance().LastError().c_str());
            ForwarderClient::NoteFailure(std::string("forwarder call ") + mName + ": " + ForwarderStream::Instance().LastError(),
                                       ForwarderStream::Instance().LastFailure());
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

void registerCommandsForwarder(Commands & commands, CredentialIssuerCommands * credsIssuerConfig)
{
    commands_list clusterCommands = {
        make_unique<ForwarderCallCommand>(credsIssuerConfig),
    };
    commands.RegisterCommandSet("Forwarder", clusterCommands, "The forwarder's own commands.");
}
