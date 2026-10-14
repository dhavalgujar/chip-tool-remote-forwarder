// SPDX-License-Identifier: Apache-2.0

// The cloud signer: while a gateway call runs, this controller's fabric CA
// verifies each device's attestation and signs its certificate (and, during
// matter.enroll, the gateway's own); see GatewayClient.h and mgw_proto.h.
#include "GatewayClient.h"

#include <string.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <vector>

#include <credentials/attestation_verifier/DeviceAttestationVerifier.h>
#include <crypto/CHIPCryptoPAL.h>
#include <lib/support/logging/CHIPLogging.h>
#include <platform/CHIPDeviceLayer.h>

#include "GatewayStream.h"
#include "mgw_proto.h"

using namespace chip;

namespace GatewayClient {

namespace {

// How long the CHIP thread may take to verify or sign (the gateway's own
// deadline is gateway_ca.cpp's kSignTimeoutMs, the same).
constexpr auto kSignTimeout = std::chrono::seconds(20);

// The running gateway call's commissioner (null: no call, nothing is signed).
std::atomic<Controller::DeviceCommissioner *> sCommissioner{ nullptr };
std::atomic<bool> sEnrolling{ false };
std::mutex sSignLock; // one at a time

// The last attestation verified here: a device NOC is signed only for it.
std::vector<uint8_t> sAttestedDac, sAttestedChallenge;

struct SignJob
{
    uint8_t kind = 0;
    NodeId node  = kUndefinedNodeId;
    uint64_t fabric = 0;
    // kinds 1, 2: NOCSR elements, attestation signature, challenge, CSR nonce, DAC, PAI
    // kind 3: attestation elements, challenge, attestation signature, PAI, DAC, nonce
    // (spans into own copies: the job can outlive the request it came in)
    std::vector<uint8_t> bytes[6];
    ByteSpan f[6];
    ByteSpan & nocsr     = f[0];
    ByteSpan & attSig    = f[1];
    ByteSpan & challenge = f[2];
    ByteSpan & csrNonce  = f[3];
    ByteSpan & dac       = f[4];
    ByteSpan & pai       = f[5];
    uint16_t result      = 0; // kind 3: AttestationVerificationResult
    bool revocationChecked = false;
    std::unique_ptr<Credentials::DeviceAttestationVerifier::AttestationInfo> info;
    Callback::Callback<Credentials::DeviceAttestationVerifier::OnAttestationInformationVerification> attestCb{ OnAttest, this };

    std::mutex m;
    std::condition_variable cv;
    bool done       = false;
    uint16_t status = mgw::kErrSigner;
    std::vector<uint8_t> noc, icac, rcac, ipk;
    uint64_t admin = 0;
    Callback::Callback<Controller::OnNOCChainGeneration> cb{ OnChain, this };

    void Finish(uint16_t s)
    {
        std::lock_guard<std::mutex> l(m);
        status = s;
        done   = true;
        cv.notify_one();
    }

    static void OnChain(void * ctx, CHIP_ERROR err, const ByteSpan & noc, const ByteSpan & icac, const ByteSpan & rcac,
                        Optional<Crypto::IdentityProtectionKeySpan> ipk, Optional<NodeId> admin)
    {
        auto * j = static_cast<SignJob *>(ctx);
        if (err != CHIP_NO_ERROR || !ipk.HasValue())
        {
            ChipLogError(chipTool, "Gateway signer: NOC chain failed: %" CHIP_ERROR_FORMAT, err.Format());
            j->Finish(mgw::kErrSigner);
            return;
        }
        j->noc.assign(noc.begin(), noc.end());
        j->icac.assign(icac.begin(), icac.end());
        j->rcac.assign(rcac.begin(), rcac.end());
        j->ipk.assign(ipk.Value().begin(), ipk.Value().end());
        j->admin = admin.ValueOr(0);
        j->Finish(mgw::kErrNone);
    }

    // CHIP's verifier (PAA, chain, CD, nonce, VID/PID), then revocation.
    static void OnAttest(void * ctx, const Credentials::DeviceAttestationVerifier::AttestationInfo & info,
                         Credentials::AttestationVerificationResult result)
    {
        auto * j = static_cast<SignJob *>(ctx);
        if (result == Credentials::AttestationVerificationResult::kSuccess && !j->revocationChecked)
        {
            j->revocationChecked = true;
            auto * c             = sCommissioner.load(); // the call may have ended meanwhile
            if (c == nullptr || c->GetDeviceAttestationVerifier() == nullptr)
            {
                j->Finish(mgw::kErrSigner);
                return;
            }
            c->GetDeviceAttestationVerifier()->CheckForRevokedDACChain(info, &j->attestCb);
            return;
        }
        j->result = static_cast<uint16_t>(result);
        if (result == Credentials::AttestationVerificationResult::kSuccess)
        {
            ByteSpan dac = j->info->dacDerBuffer, challenge = j->info->attestationChallengeBuffer;
            sAttestedDac.assign(dac.begin(), dac.end());
            sAttestedChallenge.assign(challenge.begin(), challenge.end());
            ChipLogProgress(chipTool, "Gateway attestation: verified (VID 0x%04x PID 0x%04x)", static_cast<unsigned>(j->node),
                            static_cast<unsigned>(j->fabric));
            j->Finish(mgw::kErrNone);
        }
        else
        {
            ChipLogError(chipTool, "Gateway attestation: refused (%u)", static_cast<unsigned>(result));
            j->Finish(mgw::kErrAttestation);
        }
    }
};

// The NOCSR (with the CSR in it) must be signed by the device's DAC for this
// PASE session (the attestation itself was verified just before: kind 3).
uint16_t CheckCsr(SignJob & j, Controller::DeviceCommissioner * commissioner)
{
    auto * verifier = commissioner->GetDeviceAttestationVerifier();
    Crypto::P256PublicKey dacKey;
    CHIP_ERROR err = j.dac.empty() ? CHIP_ERROR_INVALID_ARGUMENT : Crypto::ExtractPubkeyFromX509Cert(j.dac, dacKey);
    if (err == CHIP_NO_ERROR)
    {
        err = verifier == nullptr ? CHIP_ERROR_INCORRECT_STATE
                                  : verifier->VerifyNodeOperationalCSRInformation(j.nocsr, j.challenge, j.attSig, dacKey, j.csrNonce);
    }
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(chipTool, "Gateway signer: the CSR is not signed by the device's DAC for this session: %" CHIP_ERROR_FORMAT,
                     err.Format());
        return mgw::kErrAttestation;
    }
    return mgw::kErrNone;
}

void AttestInChipTask(SignJob & j, Controller::DeviceCommissioner * commissioner)
{
    auto * verifier = commissioner->GetDeviceAttestationVerifier();
    if (verifier == nullptr)
    {
        j.Finish(mgw::kErrSigner);
        return;
    }
    // fields: elements, challenge, signature, PAI, DAC, nonce; VID and PID in the node and fabric slots
    j.info = std::make_unique<Credentials::DeviceAttestationVerifier::AttestationInfo>(
        j.f[0], j.f[1], j.f[2], j.f[3], j.f[4], j.f[5], static_cast<VendorId>(j.node), static_cast<uint16_t>(j.fabric));
    verifier->VerifyAttestationInformation(*j.info, &j.attestCb);
}

void SignInChipTask(intptr_t arg)
{
    auto * j                  = reinterpret_cast<SignJob *>(arg);
    auto * const commissioner = sCommissioner.load();
    if (commissioner == nullptr)
    {
        j->Finish(mgw::kErrSigner);
        return;
    }
    switch (j->kind)
    {
    case mgw::kSignAttest:
        AttestInChipTask(*j, commissioner);
        return;
    case mgw::kSignDevice: {
        // Only for the device whose attestation was just verified here.
        bool attested = !sAttestedDac.empty() && j->dac.data_equal(ByteSpan(sAttestedDac.data(), sAttestedDac.size())) &&
            j->challenge.data_equal(ByteSpan(sAttestedChallenge.data(), sAttestedChallenge.size()));
        if (!attested)
        {
            ChipLogError(chipTool, "Gateway signer: no verified attestation for this device; refusing to sign");
            j->Finish(mgw::kErrAttestation);
            return;
        }
        uint16_t a = CheckCsr(*j, commissioner);
        if (a != mgw::kErrNone)
        {
            j->Finish(a);
            return;
        }
        sAttestedDac.clear();
        sAttestedChallenge.clear();
        break;
    }
    case mgw::kSignController:
        // Only while this controller enrolls the gateway, and only into its fabric.
        if (!sEnrolling.load() || j->fabric != commissioner->GetFabricId())
        {
            ChipLogError(chipTool, "Gateway signer: a controller certificate the user didn't ask for (matter.enroll); refusing");
            j->Finish(mgw::kErrSigner);
            return;
        }
        break;
    default:
        ChipLogError(chipTool, "Gateway signer: unknown request kind %u", static_cast<unsigned>(j->kind));
        j->Finish(mgw::kErrSigner);
        return;
    }
    CHIP_ERROR err = commissioner->IssueNOCChain(j->nocsr, j->node, &j->cb);
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(chipTool, "Gateway signer: IssueNOCChain: %" CHIP_ERROR_FORMAT, err.Format());
        j->Finish(mgw::kErrSigner);
    }
}

// A sign request (the body after the op byte), on a thread of the stream:
// returns the signed body (after the op byte), or empty if it can't be parsed
// or answered in time.
std::vector<uint8_t> Sign(const uint8_t * req, size_t len)
{
    std::lock_guard<std::mutex> one(sSignLock);
    if (sCommissioner.load() == nullptr)
        return {}; // no gateway call running: nothing is signed
    // sign: req, kind, node, fabric, then six fields (mgw_proto.h)
    mgw::FieldReader in(req, len);
    uint16_t reqId;
    auto job = std::make_unique<SignJob>();
    if (!in.U16(reqId) || !in.U8(job->kind) || !in.U64(job->node) || !in.U64(job->fabric))
        return {};
    for (size_t i = 0; i < 6; i++)
    {
        const uint8_t * p;
        size_t n;
        if (!in.Field(p, n))
            return {};
        job->bytes[i].assign(p, p + n);
        job->f[i] = ByteSpan(job->bytes[i].data(), job->bytes[i].size());
    }
    if (job->kind == mgw::kSignAttest)
    {
        ChipLogProgress(chipTool, "Gateway attestation: device VID 0x%04x PID 0x%04x", static_cast<unsigned>(job->node),
                        static_cast<unsigned>(job->fabric));
    }
    else
    {
        ChipLogProgress(chipTool, "Gateway signer: %s 0x" ChipLogFormatX64,
                        job->kind == mgw::kSignDevice ? "node" : "the gateway's controller", ChipLogValueX64(job->node));
    }

    if (DeviceLayer::PlatformMgr().ScheduleWork(SignInChipTask, reinterpret_cast<intptr_t>(job.get())) == CHIP_NO_ERROR)
    {
        std::unique_lock<std::mutex> l(job->m);
        if (!job->cv.wait_for(l, kSignTimeout, [&] { return job->done; }))
        {
            // the callback may still come: leave the job (a few hundred bytes) behind
            job.release();
            return {};
        }
    }
    // signed: req, status, then (kind 3) the verifier's result, or fields NOC,
    // ICAC, RCAC, IPK and the admin subject u64
    std::vector<uint8_t> o(2 + 2 + 2 + 4 * 2 + job->noc.size() + job->icac.size() + job->rcac.size() + job->ipk.size() + 8);
    mgw::FieldWriter out(o.data(), o.size());
    out.U16(reqId);
    out.U16(job->status);
    if (job->kind == mgw::kSignAttest)
    {
        out.U16(job->status == mgw::kErrSigner ? static_cast<uint16_t>(Credentials::AttestationVerificationResult::kInternalError)
                                               : job->result);
    }
    else if (job->status == mgw::kErrNone)
    {
        out.Field(job->noc.data(), job->noc.size());
        out.Field(job->icac.data(), job->icac.size());
        out.Field(job->rcac.data(), job->rcac.size());
        out.Field(job->ipk.data(), job->ipk.size());
        out.U64(job->admin);
        ChipLogProgress(chipTool, "Gateway signer: signed (%u + %u + %u bytes)", static_cast<unsigned>(job->noc.size()),
                        static_cast<unsigned>(job->icac.size()), static_cast<unsigned>(job->rcac.size()));
    }
    if (!out.Ok())
        return {};
    o.resize(out.Len());
    return o;
}

} // namespace

void SetSigner(Controller::DeviceCommissioner * commissioner, bool enrolling)
{
    VerifyOrReturn(Enabled());
    sEnrolling    = enrolling && commissioner != nullptr;
    sCommissioner = commissioner;
    GatewayStream::Instance().SetSignHandler(Sign);
}

} // namespace GatewayClient
