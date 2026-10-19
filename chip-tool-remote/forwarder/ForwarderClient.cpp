// SPDX-License-Identifier: Apache-2.0

#include "ForwarderClient.h"

#include <mutex>

#include "ctf_proto.h"

namespace ForwarderClient {

namespace {
std::mutex sFailureLock;
std::string sFailure;
} // namespace

bool Enabled()
{
    return ForwarderStream::Instance().Configured();
}

void NoteFailure(const std::string & reason, ForwarderStream::Failure kind)
{
    using Failure = ForwarderStream::Failure;
    std::string hint;
    switch (kind)
    {
    case Failure::kUnknownSecret:
        hint = " (the secret changed: get the forwarder's current endpoint and secret again and rewrite connect.json)";
        break;
    case Failure::kProxyAuth:
        hint = " (the proxy wants other credentials: check HTTPS_PROXY or CHIP_TOOL_REMOTE_PROXY)";
        break;
    case Failure::kOldProtocol:
        hint = std::string(" (chip-tool-remote and the forwarder's firmware must both speak ") + ctf::kAlpn +
            ": update the older one)";
        break;
    case Failure::kProxyRefused:
        hint = " (the forwarder's address may have changed: get its current endpoint and secret again and rewrite connect.json;"
               " otherwise the proxy doesn't let this machine reach that address)";
        break;
    case Failure::kUnreachable:
        hint = " (is the forwarder online? Its address may have changed: get its current endpoint and secret again and rewrite"
               " connect.json)";
        break;
    case Failure::kPolicy:
        hint = " (this forwarder didn't commission that node: see forwarder call matter.nodes)";
        break;
    default:
        break;
    }
    std::lock_guard<std::mutex> l(sFailureLock);
    sFailure = reason + hint;
}

std::string LastFailure()
{
    std::lock_guard<std::mutex> l(sFailureLock);
    return sFailure;
}

} // namespace ForwarderClient
