// SPDX-License-Identifier: Apache-2.0

/* Sleepy devices (ICDs): this controller is their ICD client.
 *
 * Commissioning registers this controller (its own node ID on the fabric) as
 * the device's Check-In client, with a key of its own per device. A LIT
 * device then sends a Check-In to this node when it wakes up; CHIP's
 * CheckInHandler checks it and calls us on the CHIP thread. We note the time,
 * tell the listener (the forwarder: an `event` frame to the cloud controllers, whose
 * subscriptions to the node resubscribe at once) and answer matter.icd_wait
 * callers, asking the device to stay awake (StayActiveRequest) if they want.
 *
 * matter.icd       registered ICDs and their last Check-In
 * matter.icd_wait  wait for a node's next Check-In (optionally keep it awake) */
#include "controller_priv.h"

#include <cstdio>
#include <cstring>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "ctf_cmd.h"
#include "ctf_server.h"

#include <app/icd/client/DefaultICDClientStorage.h>
#include <controller/CHIPDeviceControllerFactory.h>
#include <esp_matter_controller_client.h>
#include <esp_matter_controller_pairing_command.h>
#include <app-common/zap-generated/cluster-objects.h>
#include <app/OperationalSessionSetup.h>
#include <controller/InvokeInteraction.h>
#include <platform/CHIPDeviceLayer.h>

#define TAG "ctf_icd"
#define ICD_MAX_SEEN 64
#define ICD_MAX_WAITERS 8
#define ICD_WAIT_DEFAULT_S 300
#define ICD_WAIT_MAX_S 3600
#define ICD_STAY_MAX_MS 300000 /* the spec caps a StayActiveRequest's promise at 30 s for most devices anyway */

using namespace esp_matter::controller;
using chip::ScopedNodeId;
namespace StayActiveRequest = chip::app::Clusters::IcdManagement::Commands::StayActiveRequest;
namespace StayActiveResponse = chip::app::Clusters::IcdManagement::Commands::StayActiveResponse;


typedef struct {
    uint64_t node;
    int64_t last_us;
    uint32_t checkins;
} seen_t;

typedef struct {
    bool used;
    bool fired; /* checked in: answered by the StayActiveRequest's result (deadline moved to cover it) */
    uint32_t id;
    uint64_t node;
    uint32_t stay_ms;
    int64_t t0_us;
    int64_t deadline_us;
    ctf_reply_t *reply;
} waiter_t;

static SemaphoreHandle_t s_lock;
static seen_t s_seen[ICD_MAX_SEEN];
static waiter_t s_wait[ICD_MAX_WAITERS];
static uint32_t s_next_id;
static esp_timer_handle_t s_tick;
static void (*s_listener)(uint64_t node);

extern "C" void ctf_ctl_set_icd_listener(void (*fn)(uint64_t node)) { s_listener = fn; }

/* ---- waiters ------------------------------------------------------------- */

/* Answer waiter `id` once (whoever gets here first: Check-In, StayActive
 * result or the deadline). Takes ownership of `result`. From the deadline
 * (only_if_fired: what tick saw), a waiter whose state changed since is left. */
static void complete(uint32_t id, cJSON *result, int only_if_fired = -1)
{
    ctf_reply_t *reply = NULL;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (auto &w : s_wait) {
        if (w.used && w.id == id && (only_if_fired < 0 || (int)w.fired == only_if_fired)) {
            reply = w.reply;
            memset(&w, 0, sizeof(w));
            break;
        }
    }
    xSemaphoreGive(s_lock);
    if (reply) {
        ctf_reply_send(reply, result);
    } else {
        cJSON_Delete(result);
    }
}

static cJSON *checked_in(uint64_t node, int64_t t0_us)
{
    cJSON *p = cJSON_CreateObject();
    cJSON_AddNumberToObject(p, "node_id", (double)node);
    cJSON_AddNumberToObject(p, "waited_s", (double)((esp_timer_get_time() - t0_us) / 1000) / 1000.0);
    return p;
}

static void tick(void *)
{
    int64_t now = esp_timer_get_time();
    uint32_t expired[ICD_MAX_WAITERS];
    uint64_t nodes[ICD_MAX_WAITERS];
    bool fired[ICD_MAX_WAITERS];
    int n = 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (auto &w : s_wait) {
        if (w.used && now >= w.deadline_us) {
            expired[n] = w.id;
            fired[n] = w.fired;
            nodes[n++] = w.node;
        }
    }
    xSemaphoreGive(s_lock);
    for (int i = 0; i < n; i++) {
        /* fired: it checked in, but its StayActiveRequest got neither an answer nor an error */
        complete(expired[i],
                 fired[i] ? ctf_result_err("stay_active_failed", "node %llu checked in; StayActiveRequest got no answer",
                                           (unsigned long long)nodes[i])
                          : ctf_result_err("timeout", "node %llu did not check in in time (a sleepy device "
                                                      "checks in at least once per its idle interval)",
                                           (unsigned long long)nodes[i]),
                 fired[i] ? 1 : 0);
    }
}

/* A StayActiveRequest to a node that has just checked in (CHIP thread): the
 * forwarder's session with it, then CHIP's generated request and response.
 * Answers waiter `id`, then frees itself. */
class StayActive {
public:
    StayActive(uint32_t id, uint64_t node, uint32_t stay_ms, int64_t t0_us)
        : mId(id), mNode(node), mStayMs(stay_ms), mT0Us(t0_us), mOnConnected(Connected, this), mOnFailure(Failed, this)
    {
    }

    void Start()
    {
        auto *commissioner = matter_controller_client::get_instance().get_commissioner();
        CHIP_ERROR err = commissioner ? commissioner->GetConnectedDevice((chip::NodeId)mNode, &mOnConnected, &mOnFailure)
                                      : CHIP_ERROR_INCORRECT_STATE;
        if (err != CHIP_NO_ERROR) Fail("could not send StayActiveRequest", err);
    }

private:
    static void Connected(void *ctx, chip::Messaging::ExchangeManager &exchange, const chip::SessionHandle &session)
    {
        auto *self = static_cast<StayActive *>(ctx);
        StayActiveRequest::Type request;
        request.stayActiveDuration = self->mStayMs;
        CHIP_ERROR err = chip::Controller::InvokeCommandRequest(
            &exchange, session, 0, request,
            [self](const chip::app::ConcreteCommandPath &, const chip::app::StatusIB &,
                   const StayActiveResponse::DecodableType &response) {
                cJSON *p = checked_in(self->mNode, self->mT0Us);
                cJSON_AddNumberToObject(p, "promised_active_ms", response.promisedActiveDuration);
                complete(self->mId, ctf_result_ok(p));
                chip::Platform::Delete(self);
            },
            [self](CHIP_ERROR e) {
                self->Fail(e.IsIMStatus() ? "refused StayActiveRequest" : "StayActiveRequest", e);
            });
        if (err != CHIP_NO_ERROR) self->Fail("could not send StayActiveRequest", err);
    }

    static void Failed(void *ctx, const ScopedNodeId &, CHIP_ERROR e)
    {
        static_cast<StayActive *>(ctx)->Fail("could not be reached", e);
    }

    void Fail(const char *what, CHIP_ERROR e)
    {
        complete(mId, ctf_result_err("stay_active_failed", "node %llu checked in; %s: %" CHIP_ERROR_FORMAT,
                                     (unsigned long long)mNode, what, e.Format()));
        chip::Platform::Delete(this);
    }

    uint32_t mId;
    uint64_t mNode;
    uint32_t mStayMs;
    int64_t mT0Us;
    chip::Callback::Callback<chip::OnDeviceConnected> mOnConnected;
    chip::Callback::Callback<chip::OnDeviceConnectionFailure> mOnFailure;
};

static void stay_active(uint32_t id, uint64_t node, uint32_t stay_ms, int64_t t0_us)
{
    auto *request = chip::Platform::New<StayActive>(id, node, stay_ms, t0_us);
    if (!request) {
        complete(id, ctf_result_err("out_of_memory", "node %llu checked in; no memory for StayActiveRequest",
                                    (unsigned long long)node));
        return;
    }
    request->Start();
}

/* ---- Check-In (CHIP thread) ---------------------------------------------- */

static void on_check_in(const chip::app::ICDClientInfo &info)
{
    uint64_t node = info.peer_node.GetNodeId();
    int64_t now = esp_timer_get_time();
    struct {
        uint32_t id, stay_ms;
        int64_t t0_us;
    } fire[ICD_MAX_WAITERS];
    int n = 0;
    uint32_t count = 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    seen_t *slot = NULL, *oldest = &s_seen[0];
    for (auto &s : s_seen) {
        if (s.node == node) slot = &s;
        if (s.last_us < oldest->last_us) oldest = &s;
    }
    if (!slot) {
        slot = oldest;
        memset(slot, 0, sizeof(*slot));
        slot->node = node;
    }
    slot->last_us = now;
    count = ++slot->checkins;
    for (auto &w : s_wait) {
        if (w.used && !w.fired && w.node == node) {
            w.fired = w.stay_ms > 0;
            if (w.fired) w.deadline_us = now + (int64_t)w.stay_ms * 1000 + 30 * 1000000LL; /* the request's own answer, or this */
            fire[n++] = {w.id, w.stay_ms, w.t0_us};
        }
    }
    xSemaphoreGive(s_lock);
    ESP_LOGI(TAG, "node %llu checked in (%u since boot), %d waiting", (unsigned long long)node, (unsigned)count, n);
    /* A Check-In means the device has no subscription from us; it may also
     * have restarted and lost its sessions. Next use sets up CASE afresh
     * (resumption: one round trip), as CHIP's own ICD client does. */
    auto *state = chip::Controller::DeviceControllerFactory::GetInstance().GetSystemState();
    if (state && state->SessionMgr()) {
        state->SessionMgr()->MarkSessionsAsDefunct(info.peer_node,
                                                   chip::MakeOptional(chip::Transport::SecureSession::Type::kCASE));
    }
    if (s_listener) s_listener(node);
    for (int i = 0; i < n; i++) {
        if (fire[i].stay_ms > 0) {
            stay_active(fire[i].id, node, fire[i].stay_ms, fire[i].t0_us);
        } else {
            complete(fire[i].id, ctf_result_ok(checked_in(node, fire[i].t0_us)));
        }
    }
}

/* ---- hooks from controller.cpp -------------------------------------------- */

/* A sleepy device we are the ICD client of. */
static bool registered_in_chip_task(uint64_t node)
{
    auto &storage = matter_controller_client::get_instance().get_icd_client_storage();
    auto *iter = storage.IterateICDClientInfo();
    if (!iter) return false;
    chip::app::DefaultICDClientStorage::ICDClientInfoIteratorWrapper wrapper(iter);
    chip::app::ICDClientInfo info;
    while (iter->Next(info)) {
        if (info.peer_node.GetNodeId() == node) return true;
    }
    return false;
}

void ctf_ctl_icd_setup_in_chip_task(void)
{
    matter_controller_client::get_instance().set_icd_client_callback(on_check_in, nullptr);
}

/* esp-matter's pairing delegate, except that each device gets an ICD key of
 * its own: esp-matter draws one key per boot and registers every ICD with it,
 * so a Check-In could be matched to the wrong device. */
class PairingDelegate : public chip::Controller::DevicePairingDelegate
{
public:
    CHIP_ERROR Prepare(chip::Controller::CommissioningParameters &params, chip::NodeId self)
    {
        mRegistered = false;
        mStoreFailed = false;
        ReturnErrorOnFailure(chip::Crypto::DRBG_get_bytes(mKey, sizeof(mKey))); /* never a zero key */
        /* CHIP registers only devices that are LIT ICDs. */
        params.SetICDRegistrationStrategy(chip::Controller::ICDRegistrationStrategy::kBeforeComplete)
            .SetICDClientType(chip::app::Clusters::IcdManagement::ClientTypeEnum::kPermanent)
            .SetICDCheckInNodeId(self)
            .SetICDMonitoredSubject(self)
            .SetICDSymmetricKey(chip::ByteSpan(mKey));
        return CHIP_NO_ERROR;
    }

    /* The watchdog stopped this commissioning: CHIP won't report it here. */
    void Abort(chip::NodeId node)
    {
        memset(mKey, 0, sizeof(mKey));
        if (mRegistered) {
            auto &c = matter_controller_client::get_instance();
            LogErrorOnFailure(c.get_icd_client_storage().DeleteEntry(ScopedNodeId(node, c.get_fabric_index())));
            mRegistered = false;
        }
    }

    /* Whether the last commissioning registered the device but couldn't store its key. */
    bool TakeStoreFailure()
    {
        bool failed = mStoreFailed;
        mStoreFailed = false;
        return failed;
    }

    void OnStatusUpdate(chip::Controller::DevicePairingDelegate::Status status) override
    {
        esp().OnStatusUpdate(status);
        if (status == SecurePairingFailed) ctf_ctl_pairing_failed();
    }
    void OnPairingComplete(CHIP_ERROR error) override { esp().OnPairingComplete(error); }
    void OnCommissioningSuccess(chip::PeerId peer) override
    {
        memset(mKey, 0, sizeof(mKey));
        esp().OnCommissioningSuccess(peer);
    }
    void OnCommissioningFailure(chip::PeerId peer, CHIP_ERROR error, chip::Controller::CommissioningStage stage,
                                chip::Optional<chip::Credentials::AttestationVerificationResult> info) override
    {
        memset(mKey, 0, sizeof(mKey));
        auto &c = matter_controller_client::get_instance();
        if (mRegistered) LogErrorOnFailure(c.get_icd_client_storage().DeleteEntry(ScopedNodeId(peer.GetNodeId(), c.get_fabric_index())));
        esp().OnCommissioningFailure(peer, error, stage, info);
    }
    void OnICDRegistrationComplete(ScopedNodeId device, uint32_t counter) override
    {
        auto &c = matter_controller_client::get_instance();
        chip::NodeId self = c.get_commissioner()->GetNodeId();
        chip::app::ICDClientInfo info;
        info.check_in_node = ScopedNodeId(self, device.GetFabricIndex());
        info.peer_node = device;
        info.monitored_subject = self;
        info.start_icd_counter = counter;
        CHIP_ERROR err = c.get_icd_client_storage().SetKey(info, chip::ByteSpan(mKey));
        if (err == CHIP_NO_ERROR) err = c.get_icd_client_storage().StoreEntry(info);
        if (err != CHIP_NO_ERROR) {
            c.get_icd_client_storage().RemoveKey(info);
            ESP_LOGE(TAG, "node %llu: ICD registration not stored: %" CHIP_ERROR_FORMAT,
                     (unsigned long long)device.GetNodeId(), err.Format());
            mStoreFailed = true;
            return;
        }
        mRegistered = true;
    }
    void OnICDStayActiveComplete(ScopedNodeId device, uint32_t promised) override
    {
        esp().OnICDStayActiveComplete(device, promised);
    }

private:
    static pairing_command &esp() { return pairing_command::get_instance(); }

    uint8_t mKey[chip::Crypto::kAES_CCM128_Key_Length] = {};
    bool mRegistered = false;
    bool mStoreFailed = false;
};

static PairingDelegate s_pairing_delegate;

chip::Controller::DevicePairingDelegate *ctf_ctl_icd_prepare_commission(chip::Controller::CommissioningParameters &params)
{
    CHIP_ERROR err = s_pairing_delegate.Prepare(params, matter_controller_client::get_instance().get_commissioner()->GetNodeId());
    return err == CHIP_NO_ERROR ? &s_pairing_delegate : nullptr;
}

void ctf_ctl_icd_abort_in_chip_task(uint64_t node) { s_pairing_delegate.Abort((chip::NodeId)node); }

bool ctf_ctl_icd_take_store_failure(void) { return s_pairing_delegate.TakeStoreFailure(); }

static void forget_in_chip_task(intptr_t arg)
{
    const uint64_t node = ctf_ctl_take_node(arg);
    auto &c = matter_controller_client::get_instance();
    CHIP_ERROR err = c.get_icd_client_storage().DeleteEntry(ScopedNodeId((chip::NodeId)node, c.get_fabric_index()));
    if (err == CHIP_NO_ERROR) ESP_LOGI(TAG, "node %llu: ICD registration forgotten", (unsigned long long)node);
}

void ctf_ctl_icd_forget(uint64_t node)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (auto &s : s_seen) {
        if (s.node == node) memset(&s, 0, sizeof(s));
    }
    xSemaphoreGive(s_lock);
    if (!ctf_ctl_schedule_node(forget_in_chip_task, node)) {
        ESP_LOGW(TAG, "node %llu: its ICD registration stays until the next removal", (unsigned long long)node);
    }
}

/* ---- matter.icd ------------------------------------------------------------ */

#define ICD_LIST_MAX 24 /* about 100 bytes each */

typedef struct {
    cJSON *list;
    bool truncated;
} list_job_t;

static void list_in_chip_task(void *arg)
{
    list_job_t *j = (list_job_t *)arg;
    auto &storage = matter_controller_client::get_instance().get_icd_client_storage();
    auto *iter = storage.IterateICDClientInfo();
    if (iter) {
        chip::app::DefaultICDClientStorage::ICDClientInfoIteratorWrapper wrapper(iter);
        chip::app::ICDClientInfo info;
        int n = 0;
        while (iter->Next(info)) {
            if (++n > ICD_LIST_MAX) {
                j->truncated = true; /* the result must fit a stream frame */
                break;
            }
            cJSON *e = cJSON_CreateObject();
            cJSON_AddNumberToObject(e, "node_id", (double)info.peer_node.GetNodeId());
            cJSON_AddNumberToObject(e, "check_in_node", (double)info.check_in_node.GetNodeId());
            cJSON_AddNumberToObject(e, "counter", (double)(info.start_icd_counter + info.offset));
            cJSON_AddItemToArray(j->list, e);
        }
    }
}

static cJSON *icd_cmd(const cJSON *, ctf_reply_t *)
{
    if (!ctf_ctl_started()) return ctf_ctl_not_started();
    list_job_t j = {cJSON_CreateArray(), false};
    if (!j.list) return ctf_result_err("out_of_memory", "no memory");
    ctf::RunInChipTask(list_in_chip_task, &j);
    int64_t now = esp_timer_get_time();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    cJSON *e;
    cJSON_ArrayForEach(e, j.list)
    {
        uint64_t node = (uint64_t)cJSON_GetObjectItemCaseSensitive(e, "node_id")->valuedouble;
        for (auto &s : s_seen) {
            if (s.node == node && s.checkins) {
                cJSON_AddNumberToObject(e, "last_check_in_s_ago", (double)((now - s.last_us) / 1000000));
                cJSON_AddNumberToObject(e, "check_ins", s.checkins);
            }
        }
    }
    int waiting = 0;
    for (auto &w : s_wait) waiting += w.used ? 1 : 0;
    xSemaphoreGive(s_lock);
    cJSON *p = cJSON_CreateObject();
    cJSON_AddItemToObject(p, "icds", j.list);
    if (j.truncated) cJSON_AddBoolToObject(p, "truncated", true);
    cJSON_AddNumberToObject(p, "waiting", waiting);
    return ctf_result_ok(p);
}

/* ---- matter.icd_wait ------------------------------------------------------- */

static cJSON *icd_wait_cmd(const cJSON *params, ctf_reply_t *reply)
{
    if (!ctf_ctl_started()) return ctf_ctl_not_started();
    uint64_t node = (uint64_t)ctf_param_int(params, "node_id", 0);
    if (!ctf_ctl_node_known(node)) return ctf_ctl_unknown_node(node);
    struct {
        uint64_t node;
        bool icd;
    } q = {node, false};
    ctf::RunInChipTask([](void *a) {
        auto *x = static_cast<decltype(q) *>(a);
        x->icd = registered_in_chip_task(x->node);
    }, &q);
    if (!q.icd) {
        return ctf_result_err("not_icd", "node %llu is not a sleepy device this forwarder is the check-in client of "
                                         "(see matter.icd)", (unsigned long long)node);
    }
    long long timeout_s = ctf_param_int(params, "timeout_s", ICD_WAIT_DEFAULT_S);
    long long stay_ms = ctf_param_int(params, "stay_active_ms", 0);
    if (timeout_s < 1 || timeout_s > ICD_WAIT_MAX_S) {
        return ctf_result_err("invalid_param", "timeout_s must be 1-%d", ICD_WAIT_MAX_S);
    }
    if (stay_ms < 0 || stay_ms > ICD_STAY_MAX_MS) {
        return ctf_result_err("invalid_param", "stay_active_ms must be 0-%d", ICD_STAY_MAX_MS);
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    waiter_t *w = NULL;
    for (auto &x : s_wait) {
        if (!x.used) {
            w = &x;
            break;
        }
    }
    if (w) {
        w->used = true;
        w->id = ++s_next_id;
        w->node = node;
        w->stay_ms = (uint32_t)stay_ms;
        w->t0_us = esp_timer_get_time();
        w->deadline_us = w->t0_us + timeout_s * 1000000LL;
        w->reply = reply;
    }
    xSemaphoreGive(s_lock);
    if (!w) return ctf_result_err("busy", "%d callers are already waiting", ICD_MAX_WAITERS);
    ESP_LOGI(TAG, "waiting up to %lld s for node %llu to check in", timeout_s, (unsigned long long)node);
    return CTF_ASYNC;
}

/* ---- registration ---------------------------------------------------------- */

/* node_id: the sleepy device. timeout_s: how long to wait, 1-3600 s (default
 * 300). stay_active_ms: then ask it to stay awake this long, to send it
 * commands. */
static const ctf_param_t wait_req[] = {{"node_id", CTF_PARAM_INTEGER}};
static const ctf_param_t wait_opt[] = {{"timeout_s", CTF_PARAM_INTEGER}, {"stay_active_ms", CTF_PARAM_INTEGER}};

static const ctf_cmd_def_t s_cmds[] = {
    /* Sleepy devices (ICDs) registered to check in with this forwarder, with
     * their last check-in. */
    {.name = "matter.icd", .fn = icd_cmd},
    /* Wait until a sleepy device checks in (wakes up); optionally keep it
     * awake to talk to it. */
    {.name = "matter.icd_wait",
     .required = wait_req,
     .n_required = 1,
     .optional = wait_opt,
     .n_optional = 2,
     .timeout_ms = (ICD_WAIT_MAX_S + 60) * 1000,
     .fn = icd_wait_cmd},
};

void ctf_ctl_icd_register(void)
{
    static StaticSemaphore_t lock_buf;
    s_lock = xSemaphoreCreateMutexStatic(&lock_buf);
    const esp_timer_create_args_t args = {.callback = tick, .arg = NULL, .dispatch_method = ESP_TIMER_TASK,
                                          .name = "ctf_icd_tick", .skip_unhandled_events = true};
    if (esp_timer_create(&args, &s_tick) == ESP_OK) esp_timer_start_periodic(s_tick, 1000000);
    for (const auto &c : s_cmds) ctf_cmd_register(&c);
}
