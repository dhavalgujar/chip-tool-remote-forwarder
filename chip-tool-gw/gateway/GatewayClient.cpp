// SPDX-License-Identifier: Apache-2.0

#include "GatewayClient.h"

#include <mutex>

#include "mgw_proto.h"

namespace GatewayClient {

namespace {
std::mutex sFailureLock;
std::string sFailure;
} // namespace

bool Enabled()
{
    return GatewayStream::Instance().Configured();
}

void NoteFailure(const std::string & reason, GatewayStream::Failure kind)
{
    using Failure = GatewayStream::Failure;
    std::string hint;
    switch (kind)
    {
    case Failure::kUnknownSecret:
        hint = " (the secret changed: get the gateway's current endpoint and secret again and rewrite connect.json)";
        break;
    case Failure::kProxyAuth:
        hint = " (the proxy wants other credentials: check HTTPS_PROXY or MATTER_GW_PROXY)";
        break;
    case Failure::kOldProtocol:
        hint = std::string(" (chip-tool-gw and the gateway's firmware must both speak ") + mgw::kAlpn + ": update the older one)";
        break;
    case Failure::kProxyRefused:
        hint = " (the gateway's address may have changed: get its current endpoint and secret again and rewrite connect.json;"
               " otherwise the proxy doesn't let this machine reach that address)";
        break;
    case Failure::kUnreachable:
        hint = " (is the gateway online? Its address may have changed: get its current endpoint and secret again and rewrite"
               " connect.json)";
        break;
    case Failure::kPolicy:
        hint = " (this gateway didn't commission that node: see gateway call matter.nodes)";
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

} // namespace GatewayClient
