// SPDX-License-Identifier: Apache-2.0

/*
 * The fabric's CA in the cloud. An esp-matter credentials issuer
 * whose certificates come from the cloud controller (its own fabric CA, e.g.
 * chip-tool's), asked over the forwarder stream (ctf_proto.h sign/signed):
 *
 * - Enrollment (matter.enroll, from a cloud controller): this device makes its
 *   own operational key, the cloud signs it; key and chain are kept in NVS and
 *   become the controller's identity from the next boot.
 * - Commissioning (once enrolled): the node's CSR, with its DAC, PAI and the
 *   attestation signature, goes to the cloud controller that asked for the
 *   commissioning; it checks them and returns the node's NOC chain.
 *
 * - Attestation: the commissioner's attestation verifier is the cloud's
 *   (CloudVerifier): the device's attestation goes to the same cloud
 *   controller, which runs CHIP's verifier (PAA, CD, revocation) and answers.
 *
 * Not enrolled: nothing is commissioned (matter.enroll first). The controller
 * starts with a throwaway local identity only so that the stream runs.
 */
#include "forwarder_ca.h"
#include "forwarder.h"

#include <string.h>

#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "ctf_nvs.h"

#include <controller/CHIPDeviceController.h>
#include <controller/ExampleOperationalCredentialsIssuer.h>
#include <credentials/attestation_verifier/DeviceAttestationVerifier.h>

#include <vector>
#include <credentials/CHIPCert.h>
#include <credentials/CHIPCertificateSet.h>
#include <credentials/CertificateValidityPolicy.h>
#include <credentials/DeviceAttestationConstructor.h>
#include <credentials/FabricTable.h>
#include <lib/support/TestGroupData.h>
#include <crypto/CHIPCryptoPAL.h>
#include <esp_matter_controller_credentials_issuer.h>
#include <platform/CHIPDeviceLayer.h>

#include "ctf_proto.h"
#include "ctf_server.h"

#define TAG "ctf_ca"

using namespace chip;

namespace {

constexpr size_t kMaxCert         = Controller::kMaxCHIPDERCertLength;
constexpr uint32_t kSignTimeoutMs = 20000; // attest + sign fit the 60 s fail-safe

// The enrolled identity (PSRAM .bss: linker.lf.in).
struct Identity
{
    bool valid;
    Crypto::P256SerializedKeypair key;
    uint8_t noc[kMaxCert];
    size_t nocLen;
    uint8_t icac[kMaxCert];
    size_t icacLen;
    uint8_t rcac[kMaxCert];
    size_t rcacLen;
    uint8_t ipk[Crypto::CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES];
    NodeId node;     // this controller's, from its NOC
    FabricId fabric; // the fabric's, from its NOC
} sId;

bool sEnrolledThisBoot; // stored; the restart that uses it is pending

// A NOC chain (X.509 DER) checked as CHIP checks one it installs: each
// certificate signed by the next, the NOC an operational one. Gives its node,
// fabric and NOC key. (Validity dates are not checked: the clock may be unset.)
bool verify_chain(const ByteSpan & noc, const ByteSpan & icac, const ByteSpan & rcac, NodeId & node, FabricId & fabric,
                  Crypto::P256PublicKey & nocKey)
{
    if (noc.size() > kMaxCert || icac.size() > kMaxCert || rcac.size() > kMaxCert)
    {
        return false;
    }
    std::vector<uint8_t> buf(3 * Credentials::kMaxCHIPCertLength);
    MutableByteSpan chipNoc(buf.data(), Credentials::kMaxCHIPCertLength);
    MutableByteSpan chipIcac(buf.data() + Credentials::kMaxCHIPCertLength, Credentials::kMaxCHIPCertLength);
    MutableByteSpan chipRcac(buf.data() + 2 * Credentials::kMaxCHIPCertLength, Credentials::kMaxCHIPCertLength);
    if (Credentials::ConvertX509CertToChipCert(noc, chipNoc) != CHIP_NO_ERROR ||
        Credentials::ConvertX509CertToChipCert(rcac, chipRcac) != CHIP_NO_ERROR)
    {
        return false;
    }
    if (icac.empty())
    {
        chipIcac.reduce_size(0);
    }
    else if (Credentials::ConvertX509CertToChipCert(icac, chipIcac) != CHIP_NO_ERROR)
    {
        return false;
    }
    Credentials::IgnoreCertificateValidityPeriodPolicy policy;
    Credentials::ValidationContext ctx;
    ctx.Reset();
    ctx.mRequiredKeyUsages.Set(Credentials::KeyUsageFlags::kDigitalSignature);
    ctx.mRequiredKeyPurposes.Set(Credentials::KeyPurposeFlags::kServerAuth);
    ctx.mValidityPolicy = &policy;
    CompressedFabricId compressed;
    return FabricTable::VerifyCredentials(chipNoc, chipIcac, chipRcac, ctx, compressed, fabric, node, nocKey) == CHIP_NO_ERROR;
}

bool load_blob(nvs_handle_t h, const char * key, uint8_t * out, size_t cap, size_t & len)
{
    len = cap;
    return nvs_get_blob(h, key, out, &len) == ESP_OK;
}

bool load_identity()
{
    nvs_handle_t h;
    if (ctf_nvs_open(NVS_READONLY, &h) != ESP_OK)
    {
        return false;
    }
    size_t keyLen = 0, ipkLen = 0;
    bool ok = load_blob(h, "ca_key", sId.key.Bytes(), sId.key.Capacity(), keyLen) &&
        load_blob(h, "ca_noc", sId.noc, sizeof(sId.noc), sId.nocLen) &&
        load_blob(h, "ca_rcac", sId.rcac, sizeof(sId.rcac), sId.rcacLen) &&
        load_blob(h, "ca_ipk", sId.ipk, sizeof(sId.ipk), ipkLen) && ipkLen == sizeof(sId.ipk);
    if (ok && !load_blob(h, "ca_icac", sId.icac, sizeof(sId.icac), sId.icacLen))
    {
        sId.icacLen = 0;
    }
    nvs_close(h);
    ok = ok && sId.key.SetLength(keyLen) == CHIP_NO_ERROR;
    Crypto::P256PublicKey nocKey;
    if (ok &&
        !verify_chain(ByteSpan(sId.noc, sId.nocLen), ByteSpan(sId.icac, sId.icacLen), ByteSpan(sId.rcac, sId.rcacLen), sId.node,
                      sId.fabric, nocKey))
    {
        ESP_LOGE(TAG, "the stored enrollment is not a valid NOC chain: not enrolled");
        ok = false;
    }
    sId.valid = ok;
    return ok;
}

esp_err_t store_identity(const Crypto::P256SerializedKeypair & key, const ByteSpan & noc, const ByteSpan & icac,
                         const ByteSpan & rcac, const ByteSpan & ipk)
{
    nvs_handle_t h;
    esp_err_t err = ctf_nvs_open(NVS_READWRITE, &h);
    if (err != ESP_OK)
    {
        return err;
    }
    err = nvs_set_blob(h, "ca_key", key.ConstBytes(), key.Length());
    if (err == ESP_OK)
        err = nvs_set_blob(h, "ca_noc", noc.data(), noc.size());
    if (err == ESP_OK)
        err = icac.empty() ? (nvs_erase_key(h, "ca_icac"), ESP_OK) : nvs_set_blob(h, "ca_icac", icac.data(), icac.size());
    if (err == ESP_OK)
        err = nvs_set_blob(h, "ca_rcac", rcac.data(), rcac.size());
    if (err == ESP_OK)
        err = nvs_set_blob(h, "ca_ipk", ipk.data(), ipk.size());
    if (err == ESP_OK)
        err = nvs_commit(h);
    nvs_close(h);
    return err;
}

/* ---- a request to the cloud signer -------------------------------------- */

// One request at a time (commissioning and enrollment are one operation each).
struct Pending
{
    uint16_t req;
    uint8_t kind;
    uint32_t conn;
    // device: completed on the CHIP thread
    Callback::Callback<Controller::OnNOCChainGeneration> * onCompletion;
    // attestation: completed on the CHIP thread
    Callback::Callback<Credentials::DeviceAttestationVerifier::OnAttestationInformationVerification> * onAttest;
    // controller (enrollment): the caller waits
    SemaphoreHandle_t done;
    // the answer
    uint16_t status;
    uint8_t * body; // malloc'd copy of the signed body
    size_t len;
};

SemaphoreHandle_t sLock;
Pending sPending;
uint16_t sNextReq;
uint32_t sSignerConn; // the connection whose forwarder command is running (commissioning)

struct Signed
{
    uint16_t status = ctf::kErrSigner;
    ByteSpan noc, icac, rcac, ipk;
    uint64_t adminSubject = 0;
};

bool parse_signed(const uint8_t * body, size_t len, uint16_t & req, Signed & out)
{
    ctf::FieldReader r(body, len);
    const uint8_t *noc, *icac, *rcac, *ipk;
    size_t nocLen, icacLen, rcacLen, ipkLen;
    if (!r.U16(req) || !r.U16(out.status))
    {
        return false;
    }
    if (out.status != ctf::kErrNone)
    {
        return true;
    }
    if (!r.Field(noc, nocLen) || !r.Field(icac, icacLen) || !r.Field(rcac, rcacLen) || !r.Field(ipk, ipkLen) ||
        !r.U64(out.adminSubject) || ipkLen != Crypto::CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES || nocLen == 0 || rcacLen == 0)
    {
        return false;
    }
    out.noc  = ByteSpan(noc, nocLen);
    out.icac = ByteSpan(icac, icacLen);
    out.rcac = ByteSpan(rcac, rcacLen);
    out.ipk  = ByteSpan(ipk, ipkLen);
    return true;
}

void on_sign_timeout(System::Layer *, void *);

// The attestation being verified (the commissioner's spans are only valid
// during the call): copies, for the AttestationInfo given back.
struct AttestCopy
{
    std::vector<uint8_t> elements, challenge, signature, pai, dac, nonce;
    uint16_t vid = 0, pid = 0;
} sAttest;

void complete_attest(const Pending & p)
{
    using Result = Credentials::AttestationVerificationResult;
    Result result = Result::kInternalError;
    if (p.body != nullptr && p.len >= 6)
    {
        const uint16_t status = ctf::Get16(p.body + 2);
        result                = static_cast<Result>(ctf::Get16(p.body + 4));
        if (status != ctf::kErrNone && result == Result::kSuccess)
        {
            result = Result::kInternalError;
        }
    }
    ESP_LOGI(TAG, "cloud attestation: %s (%u)", p.body == nullptr ? "no answer" : result == Result::kSuccess ? "verified" : "refused",
             static_cast<unsigned>(result));
    auto bytes = [](const std::vector<uint8_t> & v) { return ByteSpan(v.data(), v.size()); };
    Credentials::DeviceAttestationVerifier::AttestationInfo info(bytes(sAttest.elements), bytes(sAttest.challenge),
                                                                 bytes(sAttest.signature), bytes(sAttest.pai), bytes(sAttest.dac),
                                                                 bytes(sAttest.nonce), static_cast<VendorId>(sAttest.vid),
                                                                 sAttest.pid);
    p.onAttest->mCall(p.onAttest->mContext, info, result);
}

void * timer_ctx(uint16_t req)
{
    return reinterpret_cast<void *>(static_cast<uintptr_t>(req));
}

// The device being commissioned: what its NOC chain must say.
struct Expect
{
    NodeId node;
    Crypto::P256PublicKey key; // from its CSR
} sExpect;

// Why the signer's chain for the device can't be used ("" if it can).
const char * check_device_chain(const Signed & s)
{
    NodeId node;
    FabricId fabric;
    Crypto::P256PublicKey nocKey;
    if (s.rcac.size() != sId.rcacLen || memcmp(s.rcac.data(), sId.rcac, sId.rcacLen) != 0)
    {
        return "not this fabric's root";
    }
    if (!verify_chain(s.noc, s.icac, s.rcac, node, fabric, nocKey))
    {
        return "not a valid NOC chain";
    }
    if (node != sExpect.node || fabric != sId.fabric)
    {
        return "for another node or fabric";
    }
    if (!nocKey.Matches(sExpect.key))
    {
        return "not for the device's key";
    }
    if (s.ipk.size() != sizeof(sId.ipk) || memcmp(s.ipk.data(), sId.ipk, sizeof(sId.ipk)) != 0)
    {
        return "another IPK";
    }
    if (s.adminSubject != 0 && s.adminSubject != sId.node)
    {
        return "another administrator";
    }
    return "";
}

// The answer to request `req` (or its timeout), on the CHIP thread; a stale one
// (the request was cancelled, or already answered) is dropped.
void complete_device_in_chip_task(intptr_t req)
{
    xSemaphoreTake(sLock, portMAX_DELAY);
    if (sPending.kind == 0 || sPending.req != static_cast<uint16_t>(req))
    {
        xSemaphoreGive(sLock);
        return;
    }
    Pending p = sPending;
    sPending  = Pending{};
    xSemaphoreGive(sLock);
    DeviceLayer::SystemLayer().CancelTimer(on_sign_timeout, timer_ctx(p.req));
    if (p.kind == ctf::kSignAttest && p.onAttest != nullptr)
    {
        complete_attest(p);
        free(p.body);
        return;
    }
    if (p.onCompletion == nullptr)
    {
        free(p.body);
        return;
    }
    Signed s;
    CHIP_ERROR err = CHIP_ERROR_INTERNAL;
    uint16_t answered;
    if (p.body != nullptr && parse_signed(p.body, p.len, answered, s))
    {
        err = s.status == ctf::kErrNone ? CHIP_NO_ERROR
                                        : (s.status == ctf::kErrAttestation ? CHIP_ERROR_INVALID_SIGNATURE : CHIP_ERROR_INTERNAL);
        const char * why = err == CHIP_NO_ERROR ? check_device_chain(s) : "";
        if (*why)
        {
            ESP_LOGE(TAG, "cloud signer: the NOC chain is %s; not used", why);
            s.status = ctf::kErrSigner;
            err      = CHIP_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (p.body == nullptr)
    {
        err = CHIP_ERROR_TIMEOUT;
    }
    if (err != CHIP_NO_ERROR)
    {
        ESP_LOGE(TAG, "cloud signer: %s", p.body ? ctf::ErrName(s.status) : "no answer");
        p.onCompletion->mCall(p.onCompletion->mContext, err, ByteSpan(), ByteSpan(), ByteSpan(), NullOptional, NullOptional);
    }
    else
    {
        Crypto::IdentityProtectionKeySpan ipk(s.ipk.data());
        Optional<NodeId> admin = s.adminSubject ? MakeOptional<NodeId>(s.adminSubject) : NullOptional;
        ESP_LOGI(TAG, "cloud signer: NOC chain for the node (%u + %u + %u bytes)", (unsigned) s.noc.size(),
                 (unsigned) s.icac.size(), (unsigned) s.rcac.size());
        p.onCompletion->mCall(p.onCompletion->mContext, CHIP_NO_ERROR, s.noc, s.icac, s.rcac, MakeOptional(ipk), admin);
    }
    free(p.body);
}

void on_sign_timeout(System::Layer *, void * ctx)
{
    const uint16_t req = static_cast<uint16_t>(reinterpret_cast<uintptr_t>(ctx));
    xSemaphoreTake(sLock, portMAX_DELAY);
    bool waiting = sPending.req == req && (sPending.onCompletion != nullptr || sPending.onAttest != nullptr) &&
        sPending.body == nullptr;
    xSemaphoreGive(sLock);
    if (waiting)
    {
        complete_device_in_chip_task(req);
    }
}

// ctf::SignedHandler: on the connection's thread.
void on_signed(uint32_t conn, const uint8_t * body, size_t len)
{
    if (len < 2)
    {
        return;
    }
    const uint16_t req = ctf::Get16(body);
    xSemaphoreTake(sLock, portMAX_DELAY);
    bool ours = sPending.kind != 0 && sPending.req == req && sPending.conn == conn && sPending.body == nullptr;
    if (ours)
    {
        sPending.body = static_cast<uint8_t *>(malloc(len));
        if (sPending.body != nullptr)
        {
            memcpy(sPending.body, body, len);
            sPending.len = len;
        }
    }
    const uint8_t kind = sPending.kind;
    if (ours && kind == ctf::kSignController)
    {
        // Under the lock: the enrolling task deletes the semaphore once it
        // has taken the request back (under the lock too).
        xSemaphoreGive(sPending.done);
    }
    xSemaphoreGive(sLock);
    if (ours && kind != ctf::kSignController)
    {
        TEMPORARY_RETURN_IGNORED DeviceLayer::PlatformMgr().ScheduleWork(complete_device_in_chip_task, req);
    }
}

void clear_pending(uint16_t req)
{
    xSemaphoreTake(sLock, portMAX_DELAY);
    if (sPending.req == req)
    {
        free(sPending.body);
        sPending = Pending{};
    }
    xSemaphoreGive(sLock);
}

// Sends a sign request; fills sPending. Fields: nocsr, attSig, challenge, csrNonce, dac, pai.
bool send_sign(uint32_t conn, uint8_t kind, NodeId node, FabricId fabric, const ByteSpan * fields, size_t nFields,
               Callback::Callback<Controller::OnNOCChainGeneration> * onCompletion, SemaphoreHandle_t done,
               Callback::Callback<Credentials::DeviceAttestationVerifier::OnAttestationInformationVerification> * onAttest,
               uint16_t & reqOut)
{
    size_t cap = 1 + 2 + 1 + 8 + 8;
    for (size_t i = 0; i < nFields; i++)
    {
        cap += 2 + fields[i].size();
    }
    if (cap > ctf::kMaxFrameBody)
    {
        return false;
    }
    uint8_t * body = static_cast<uint8_t *>(malloc(cap));
    if (body == nullptr)
    {
        return false;
    }
    xSemaphoreTake(sLock, portMAX_DELAY);
    if (sPending.kind != 0)
    {
        xSemaphoreGive(sLock);
        free(body);
        return false; // one at a time
    }
    sPending              = Pending{};
    sPending.req          = ++sNextReq;
    sPending.kind         = kind;
    sPending.conn         = conn;
    sPending.onCompletion = onCompletion;
    sPending.onAttest     = onAttest;
    sPending.done         = done;
    const uint16_t req    = sPending.req;
    reqOut                = req;
    xSemaphoreGive(sLock);

    ctf::FieldWriter w(body, cap);
    w.U8(ctf::kOpSign);
    w.U16(req);
    w.U8(kind);
    w.U64(node);
    w.U64(fabric);
    for (size_t i = 0; i < nFields; i++)
    {
        w.Field(fields[i].data(), fields[i].size());
    }
    bool ok = w.Ok() && ctf_send_later(conn, body, w.Len()); // CHIP thread: not a blocking write
    free(body);
    if (!ok)
    {
        xSemaphoreTake(sLock, portMAX_DELAY);
        sPending = Pending{};
        xSemaphoreGive(sLock);
    }
    return ok;
}

/* ---- the issuer ----------------------------------------------------------- */

class CloudIssuer final : public esp_matter::controller::credentials_issuer, public Controller::OperationalCredentialsDelegate
{
public:
    esp_err_t initialize_credentials_issuer(PersistentStorageDelegate & storage) override
    {
        load_identity();
        ESP_LOGI(TAG, "fabric CA: %s", sId.valid ? "the cloud controller's (enrolled)" : "this device's (not enrolled)");
        // Until it enrolls, the commissioner starts with an identity of its own
        // (CHIP's example issuer); nothing is commissioned under it.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        CHIP_ERROR err = mLocal.Initialize(storage);
#pragma GCC diagnostic pop
        return err == CHIP_NO_ERROR ? ESP_OK : ESP_FAIL;
    }

    Controller::OperationalCredentialsDelegate * get_delegate() override { return this; }

    esp_err_t generate_controller_noc_chain(NodeId node, FabricId fabric, Crypto::P256Keypair & keypair, MutableByteSpan & rcac,
                                            MutableByteSpan & icac, MutableByteSpan & noc) override
    {
        if (!sId.valid)
        {
            return mLocal.GenerateNOCChainAfterValidation(node, fabric, kUndefinedCATs, keypair.Pubkey(), rcac, icac, noc) ==
                    CHIP_NO_ERROR
                ? ESP_OK
                : ESP_FAIL;
        }
        // The enrolled identity: its key replaces the commissioner's fresh one.
        Crypto::P256SerializedKeypair key;
        memcpy(key.Bytes(), sId.key.ConstBytes(), sId.key.Length());
        const bool ok = key.SetLength(sId.key.Length()) == CHIP_NO_ERROR && keypair.Deserialize(key) == CHIP_NO_ERROR &&
            CopySpanToMutableSpan(ByteSpan(sId.rcac, sId.rcacLen), rcac) == CHIP_NO_ERROR &&
            CopySpanToMutableSpan(ByteSpan(sId.noc, sId.nocLen), noc) == CHIP_NO_ERROR;
        memset(key.Bytes(), 0, key.Capacity());
        if (!ok)
        {
            return ESP_FAIL;
        }
        if (sId.icacLen)
        {
            return CopySpanToMutableSpan(ByteSpan(sId.icac, sId.icacLen), icac) == CHIP_NO_ERROR ? ESP_OK : ESP_FAIL;
        }
        icac.reduce_size(0);
        return ESP_OK;
    }

    // Commissioning, once enrolled: the cloud controller signs.
    CHIP_ERROR GenerateNOCChain(const ByteSpan & csrElements, const ByteSpan & csrNonce, const ByteSpan & attestationSignature,
                                const ByteSpan & attestationChallenge, const ByteSpan & DAC, const ByteSpan & PAI,
                                Callback::Callback<Controller::OnNOCChainGeneration> * onCompletion) override
    {
        const uint32_t conn = sSignerConn;
        if (!sId.valid)
        {
            ESP_LOGE(TAG, "not enrolled: no fabric CA to sign with (matter.enroll from the cloud controller first)");
            return CHIP_ERROR_INCORRECT_STATE;
        }
        if (conn == 0)
        {
            ESP_LOGE(TAG, "commissioning needs the cloud signer: ask from a cloud controller (chip-tool-remote forwarder call)");
            return CHIP_ERROR_INCORRECT_STATE;
        }
        // What the chain that comes back must be for (check_device_chain).
        ByteSpan csr, nonce, v1, v2, v3;
        ReturnErrorOnFailure(Credentials::DeconstructNOCSRElements(csrElements, csr, nonce, v1, v2, v3));
        ReturnErrorOnFailure(Crypto::VerifyCertificateSigningRequest(csr.data(), csr.size(), sExpect.key));
        sExpect.node = mNextNode;
        const ByteSpan fields[] = { csrElements, attestationSignature, attestationChallenge, csrNonce, DAC, PAI };
        uint16_t req;
        VerifyOrReturnError(send_sign(conn, ctf::kSignDevice, mNextNode, mNextFabric, fields, 6, onCompletion, nullptr, nullptr, req),
                            CHIP_ERROR_CONNECTION_ABORTED);
        CHIP_ERROR err =
            DeviceLayer::SystemLayer().StartTimer(System::Clock::Milliseconds32(kSignTimeoutMs), on_sign_timeout, timer_ctx(req));
        if (err != CHIP_NO_ERROR)
        {
            clear_pending(req); // no answer could ever end it
            return err;
        }
        ESP_LOGI(TAG, "node 0x%llx: CSR sent to the cloud signer (conn %u)", (unsigned long long) mNextNode, (unsigned) conn);
        return CHIP_NO_ERROR;
    }

    void SetNodeIdForNextNOCRequest(NodeId node) override { mNextNode = node; }
    void SetFabricIdForNextNOCRequest(FabricId fabric) override { mNextFabric = fabric; }

private:
    Controller::ExampleOperationalCredentialsIssuer mLocal;
    NodeId mNextNode     = kUndefinedNodeId;
    FabricId mNextFabric = kUndefinedFabricId;
};

CloudIssuer sIssuer;

/* ---- the attestation verifier: the cloud's -------------------------------- */

class CloudVerifier final : public Credentials::DeviceAttestationVerifier
{
public:
    void SetLocal(Credentials::DeviceAttestationVerifier * local) { mLocal = local; }

    void VerifyAttestationInformation(const AttestationInfo & info,
                                      Callback::Callback<OnAttestationInformationVerification> * onCompletion) override
    {
        using Result        = Credentials::AttestationVerificationResult;
        const uint32_t conn = sSignerConn;
        if (conn == 0 || !sId.valid)
        {
            ESP_LOGE(TAG, "attestation needs the cloud controller (enrolled, commissioning from chip-tool-remote forwarder call)");
            onCompletion->mCall(onCompletion->mContext, info, Result::kInternalError);
            return;
        }
        auto copy = [](const ByteSpan & b) { return std::vector<uint8_t>(b.data(), b.data() + b.size()); };
        sAttest.elements  = copy(info.attestationElementsBuffer);
        sAttest.challenge = copy(info.attestationChallengeBuffer);
        sAttest.signature = copy(info.attestationSignatureBuffer);
        sAttest.pai       = copy(info.paiDerBuffer);
        sAttest.dac       = copy(info.dacDerBuffer);
        sAttest.nonce     = copy(info.attestationNonceBuffer);
        sAttest.vid       = static_cast<uint16_t>(info.vendorId);
        sAttest.pid       = info.productId;
        const ByteSpan fields[] = { info.attestationElementsBuffer, info.attestationChallengeBuffer, info.attestationSignatureBuffer,
                                    info.paiDerBuffer, info.dacDerBuffer, info.attestationNonceBuffer };
        uint16_t req;
        if (!send_sign(conn, ctf::kSignAttest, sAttest.vid, sAttest.pid, fields, 6, nullptr, nullptr, onCompletion, req))
        {
            onCompletion->mCall(onCompletion->mContext, info, Result::kInternalError);
            return;
        }
        if (DeviceLayer::SystemLayer().StartTimer(System::Clock::Milliseconds32(kSignTimeoutMs), on_sign_timeout,
                                                  timer_ctx(req)) != CHIP_NO_ERROR)
        {
            clear_pending(req);
            onCompletion->mCall(onCompletion->mContext, info, Result::kInternalError);
            return;
        }
        ESP_LOGI(TAG, "attestation (VID 0x%04x PID 0x%04x) sent to the cloud (conn %u)", sAttest.vid, sAttest.pid,
                 (unsigned) conn);
    }

    // The cloud folds revocation into its answer.
    void CheckForRevokedDACChain(const AttestationInfo & info,
                                 Callback::Callback<OnAttestationInformationVerification> * onCompletion) override
    {
        onCompletion->mCall(onCompletion->mContext, info, Credentials::AttestationVerificationResult::kSuccess);
    }

    // Synchronous checks stay local (pure crypto; no trust store involved).
    Credentials::AttestationVerificationResult ValidateCertificationDeclarationSignature(const ByteSpan & cms,
                                                                                         ByteSpan & cd) override
    {
        return mLocal->ValidateCertificationDeclarationSignature(cms, cd);
    }
    Credentials::AttestationVerificationResult
    ValidateCertificateDeclarationPayload(const ByteSpan & cd, const ByteSpan & firmwareInfo,
                                          const Credentials::DeviceInfoForAttestation & deviceInfo) override
    {
        return mLocal->ValidateCertificateDeclarationPayload(cd, firmwareInfo, deviceInfo);
    }
    CHIP_ERROR VerifyNodeOperationalCSRInformation(const ByteSpan & nocsr, const ByteSpan & challenge, const ByteSpan & signature,
                                                   const Crypto::P256PublicKey & dacKey, const ByteSpan & csrNonce) override
    {
        return mLocal->VerifyNodeOperationalCSRInformation(nocsr, challenge, signature, dacKey, csrNonce);
    }

private:
    Credentials::DeviceAttestationVerifier * mLocal = nullptr;
};

CloudVerifier sVerifier;

} // namespace

void ctf_ca_set_signer_conn(uint32_t conn)
{
    sSignerConn = conn;
}

void ctf_ca_cancel_in_chip_task(void)
{
    xSemaphoreTake(sLock, portMAX_DELAY);
    const bool device = sPending.kind == ctf::kSignDevice || sPending.kind == ctf::kSignAttest;
    const uint16_t req = sPending.req;
    if (device)
    {
        free(sPending.body);
        sPending = Pending{};
    }
    xSemaphoreGive(sLock);
    if (device)
    {
        DeviceLayer::SystemLayer().CancelTimer(on_sign_timeout, timer_ctx(req));
    }
}

bool ctf_ca_enrolled(void)
{
    return sId.valid;
}

void ctf_ca_install_verifier(chip::Controller::DeviceCommissioner * commissioner)
{
    if (commissioner->GetDeviceAttestationVerifier() != &sVerifier)
    {
        sVerifier.SetLocal(commissioner->GetDeviceAttestationVerifier());
        commissioner->SetDeviceAttestationVerifier(&sVerifier);
    }
}

namespace {

// matter.enroll: this device's operational key, signed by the calling cloud
// controller's CA.
cJSON * enroll(uint64_t node_id, uint64_t fabric_id)
{
    const uint32_t conn = ctf::CurrentCallConnection();
    if (conn == 0)
    {
        return ctf_result_err("needs_signer", "%s",
                              "run it from a cloud controller (chip-tool-remote forwarder call matter.enroll)");
    }
    if (sId.valid || sEnrolledThisBoot)
    {
        return ctf_result_err("already_enrolled", "%s", "enrolled already; a factory reset is needed to enroll again");
    }
    Crypto::P256Keypair key;
    if (key.Initialize(Crypto::ECPKeyTarget::ECDSA) != CHIP_NO_ERROR)
    {
        return ctf_result_err("crypto", "%s", "no key");
    }
    uint8_t csr[Crypto::kMIN_CSR_Buffer_Size];
    size_t csrLen = sizeof(csr);
    uint8_t nonce[Credentials::kExpectedAttestationNonceSize];
    uint8_t nocsr[Crypto::kMIN_CSR_Buffer_Size + 64];
    MutableByteSpan nocsrSpan(nocsr);
    if (key.NewCertificateSigningRequest(csr, csrLen) != CHIP_NO_ERROR || Crypto::DRBG_get_bytes(nonce, sizeof(nonce)) != CHIP_NO_ERROR ||
        Credentials::ConstructNOCSRElements(ByteSpan(csr, csrLen), ByteSpan(nonce), ByteSpan(), ByteSpan(), ByteSpan(), nocsrSpan) !=
            CHIP_NO_ERROR)
    {
        return ctf_result_err("crypto", "%s", "CSR");
    }
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    const ByteSpan fields[] = { nocsrSpan, ByteSpan(), ByteSpan(), ByteSpan(nonce), ByteSpan(), ByteSpan() };
    uint16_t req;
    if (done == nullptr || !send_sign(conn, ctf::kSignController, node_id, fabric_id, fields, 6, nullptr, done, nullptr, req))
    {
        if (done)
            vSemaphoreDelete(done);
        return ctf_result_err("busy", "%s", "another signing request is running");
    }
    bool answered = xSemaphoreTake(done, pdMS_TO_TICKS(kSignTimeoutMs)) == pdTRUE;
    xSemaphoreTake(sLock, portMAX_DELAY);
    Pending p = sPending;
    sPending  = Pending{};
    xSemaphoreGive(sLock);
    vSemaphoreDelete(done);
    if (!answered || p.body == nullptr)
    {
        free(p.body);
        return ctf_result_err("timeout", "%s", "no answer from the cloud signer");
    }
    uint16_t answeredReq;
    Signed s;
    cJSON * result = nullptr;
    Crypto::P256PublicKey nocKey;
    Crypto::P256SerializedKeypair ser;
    NodeId node;
    FabricId fabric;
    if (!parse_signed(p.body, p.len, answeredReq, s))
    {
        result = ctf_result_err("bad_answer", "%s", "the signer's answer is malformed");
    }
    else if (s.status != ctf::kErrNone)
    {
        result = ctf_result_err("refused", "the signer refused: %s", ctf::ErrName(s.status));
    }
    else if (!verify_chain(s.noc, s.icac, s.rcac, node, fabric, nocKey))
    {
        result = ctf_result_err("bad_answer", "%s", "the NOC chain is not valid");
    }
    else if (!nocKey.Matches(key.Pubkey()) || node != node_id || fabric != fabric_id)
    {
        result = ctf_result_err("bad_answer", "%s", "the NOC is not for this device's key, node and fabric");
    }
    else if (!s.ipk.data_equal(GroupTesting::DefaultIpkValue::GetDefaultIpk()))
    {
        // esp-matter's commissioner always uses the default IPK for its own
        // fabric: with another, CASE with every device would fail.
        result = ctf_result_err("unsupported", "%s", "the fabric's IPK must be the default one");
    }
    else if (key.Serialize(ser) != CHIP_NO_ERROR || store_identity(ser, s.noc, s.icac, s.rcac, s.ipk) != ESP_OK)
    {
        result = ctf_result_err("nvs", "%s", "could not store the identity");
    }
    else
    {
        uint8_t digest[Crypto::kSHA256_Hash_Length];
        LogErrorOnFailure(Crypto::Hash_SHA256(s.rcac.data(), s.rcac.size(), digest));
        char fp[17];
        for (int i = 0; i < 8; i++)
            snprintf(fp + 2 * i, 3, "%02x", digest[i]);
        cJSON * pl = cJSON_CreateObject();
        cJSON_AddStringToObject(pl, "root_sha256_prefix", fp);
        cJSON_AddNumberToObject(pl, "node_id", static_cast<double>(node_id));
        cJSON_AddStringToObject(pl, "next", "restarting to use the cloud CA; re-commission the nodes (new fabric)");
        result = ctf_result_ok(pl);
        sEnrolledThisBoot = true;
        ESP_LOGI(TAG, "enrolled: root %s; restarting in 2 s", fp);
        if (xTaskCreate([](void *) { vTaskDelay(pdMS_TO_TICKS(2000)); esp_restart(); }, "ctf_restart", 2048, NULL, 5, NULL) !=
            pdPASS)
        {
            cJSON_ReplaceItemInObject(pl, "next", cJSON_CreateString("restart the forwarder to use the cloud CA"));
        }
    }
    memset(ser.Bytes(), 0, ser.Capacity());
    free(p.body);
    return result;
}

cJSON * enroll_cmd(const cJSON * params, ctf_reply_t *)
{
    return enroll(static_cast<uint64_t>(ctf_param_int(params, "node_id", 112233)),
                  static_cast<uint64_t>(ctf_param_int(params, "fabric_id", 1)));
}

/* node_id: this controller's node ID in the cloud fabric (default 112233).
 * fabric_id: the fabric ID (default 1). */
const ctf_param_t kEnrollParams[] = { { "node_id", CTF_PARAM_INTEGER }, { "fabric_id", CTF_PARAM_INTEGER } };

/* Join the cloud controller's fabric (once): this device's operational key is
 * signed by the calling controller's CA and kept in NVS. After the restart
 * that follows, the cloud controller verifies the attestation of and signs
 * every node this device commissions. Nothing is commissioned before. */
const ctf_cmd_def_t kEnroll = {
    .name       = "matter.enroll",
    .optional   = kEnrollParams,
    .n_optional = 2,
    .timeout_ms = 2 * kSignTimeoutMs, // one signing request, then storing the identity
    .fn         = enroll_cmd,
};

} // namespace

void ctf_ca_init(void)
{
    sLock = xSemaphoreCreateMutex();
    esp_matter::controller::set_custom_credentials_issuer(&sIssuer);
    ctf::SetSignedHandler(on_signed);
    ctf_cmd_register(&kEnroll);
}
