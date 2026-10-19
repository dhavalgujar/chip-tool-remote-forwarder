// SPDX-License-Identifier: Apache-2.0

/* The controller's commands (over the forwarder stream) on esp-matter's
 * commissioner; see controller.h.
 *
 * Threads: commands arrive on the transport's task; every CHIP call runs on
 * the CHIP thread (ScheduleWork). One operation at a time: s_op, guarded by
 * s_lock, with a generation number so that a late CHIP callback after the
 * watchdog has answered (or the other way round) is ignored. A commissioning
 * the watchdog ends keeps the slot until CHIP has stopped it, so what CHIP
 * reports while stopping can't reach the next operation. */
#include "controller_priv.h"

#include <cstdio>
#include <cstring>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "forwarder_ca.h"
#include "ctf_cmd.h"
#include "ctf_nvs.h"
#include "ctf_server.h"
#include "thread_cmds.h"

#include <controller/CommissioningDelegate.h>
#include <esp_matter.h>
#include <esp_matter_controller_client.h>
#include <esp_matter_controller_commissioning_window_opener.h>
#include <esp_matter_controller_pairing_command.h>
#include <platform/CHIPDeviceLayer.h>
#include <platform/ConnectivityManager.h>

#define TAG "ctf_ctl"
#define MAX_NODES 64
/* A device's label, in bytes (Matter's NodeLabel has the same limit). */
#define MAX_LABEL 32

using namespace esp_matter::controller;
using chip::ScopedNodeId;

/* The commissioner's identity on its own fabric. */
static constexpr chip::NodeId kControllerNodeId = 112233;
static constexpr chip::FabricId kFabricId = 1;
static constexpr uint16_t kListenPort = 5580;

/* How long an operation may take: commissioning includes Bluetooth, the cloud
 * controller's attestation check and signature, and joining the network. */
static constexpr uint32_t kCommissionMs = 300000;
static constexpr uint32_t kOperationMs = 60000; /* remove, open_window */
static constexpr uint32_t kFirstNodeId = 100;
/* matter.open_window: an enhanced window (a new passcode). */
static constexpr long long kWindowMinS = 180, kWindowMaxS = 900, kWindowDefaultS = 300;
static constexpr uint32_t kWindowPbkdfIterations = 1000;
static constexpr uint16_t kWindowTimedInvokeMs = 10000;
static constexpr uint16_t kDiscriminatorMask = 0x0FFF; /* 12 bits */
/* matter.commissionables: how long to listen for devices in pairing mode. */
static constexpr long long kDiscoverDefaultS = 4;
static constexpr long long kDiscoverMaxS = 15;

/* ---- operation slot ----------------------------------------------------- */

enum op_kind_t { OP_NONE, OP_COMMISSION, OP_REMOVE, OP_WINDOW, OP_DISCOVER };

static const char *op_name(op_kind_t k)
{
    switch (k) {
    case OP_COMMISSION: return "commission";
    case OP_REMOVE: return "remove";
    case OP_WINDOW: return "open_window";
    case OP_DISCOVER: return "commissionables";
    default: return "none";
    }
}

typedef struct {
    op_kind_t kind;
    uint32_t gen;
    ctf_reply_t *reply;
    uint64_t node;
    int64_t t0_us;
    char label[MAX_LABEL + 1];
    bool stopping; /* the watchdog is stopping it: CHIP's reports are ignored */
} op_t;

static op_t s_op;
static uint32_t s_gen;
static SemaphoreHandle_t s_lock;
static esp_timer_handle_t s_watchdog;
static bool s_started;
static char s_start_error[96];

static double elapsed_s(void) { return (esp_timer_get_time() - s_op.t0_us) / 1e6; } /* s_lock held */

/* Claim the slot; false if another operation runs. */
static bool begin(op_kind_t kind, ctf_reply_t *reply, uint64_t node, uint32_t timeout_ms, uint32_t *gen_out)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_op.kind != OP_NONE) {
        xSemaphoreGive(s_lock);
        return false;
    }
    memset(&s_op, 0, sizeof(s_op));
    s_op.kind = kind;
    s_op.gen = ++s_gen;
    s_op.reply = reply;
    s_op.node = node;
    s_op.t0_us = esp_timer_get_time();
    *gen_out = s_op.gen;
    esp_timer_stop(s_watchdog);
    esp_timer_start_once(s_watchdog, (uint64_t)timeout_ms * 1000);
    xSemaphoreGive(s_lock);
    return true;
}

/* Answer the operation `gen` (if it is still the current one) and free the
 * slot. Takes ownership of `result`. Safe from any task. */
static void finish(uint32_t gen, cJSON *result)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_op.kind == OP_NONE || s_op.gen != gen) {
        xSemaphoreGive(s_lock);
        cJSON_Delete(result);
        return;
    }
    ctf_reply_t *reply = s_op.reply;
    ESP_LOGI(TAG, "%s node %llu: %s in %.1f s", op_name(s_op.kind), (unsigned long long)s_op.node,
             ctf_result_is_ok(result) ? "ok" : "failed", elapsed_s());
    if (s_op.kind == OP_COMMISSION) ctf_ca_set_signer_conn(0);
    s_op.kind = OP_NONE;
    s_op.reply = NULL;
    esp_timer_stop(s_watchdog);
    xSemaphoreGive(s_lock);
    ctf_reply_send(reply, result);
}

/* A copy of the slot, to check whether a CHIP callback is about the current
 * operation. */
static op_t current(void)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    op_t op = s_op;
    xSemaphoreGive(s_lock);
    return op;
}

static bool schedule(void (*fn)(intptr_t), intptr_t arg)
{
    return chip::DeviceLayer::PlatformMgr().ScheduleWork(fn, arg) == CHIP_NO_ERROR;
}

/* A node ID for the CHIP thread: intptr_t is 32 bits on these chips. The work
 * takes it back with ctf_ctl_take_node(). */
bool ctf_ctl_schedule_node(void (*fn)(intptr_t), uint64_t node)
{
    uint64_t *arg = (uint64_t *)malloc(sizeof(*arg));
    if (!arg) return false;
    *arg = node;
    if (schedule(fn, (intptr_t)arg)) return true;
    free(arg);
    return false;
}

uint64_t ctf_ctl_take_node(intptr_t arg)
{
    uint64_t node = *(uint64_t *)arg;
    free((void *)arg);
    return node;
}

static cJSON *node_payload(uint64_t node)
{
    cJSON *p = cJSON_CreateObject();
    cJSON_AddNumberToObject(p, "node_id", (double)node);
    return p;
}

cJSON *ctf_ctl_unknown_node(uint64_t node)
{
    return ctf_result_err("unknown_node", "node %llu is not in the list", (unsigned long long)node);
}

static cJSON *label_too_long(void)
{
    return ctf_result_err("invalid_param", "label: at most %d bytes", MAX_LABEL);
}

static cJSON *no_chip_thread(void)
{
    return ctf_result_err("internal", "could not reach the Matter thread");
}

static cJSON *timed_out(op_kind_t kind, uint64_t node)
{
    return ctf_result_err("timeout", "matter %s for node %llu did not finish in time", op_name(kind), (unsigned long long)node);
}

/* The watchdog ended commissioning `gen`: stop it, then answer and free the slot. */
static void stop_pairing_in_chip_task(intptr_t gen)
{
    const op_t op = current();
    if (op.kind != OP_COMMISSION || op.gen != (uint32_t)gen) return;
    const uint64_t node = op.node;
    auto &c = matter_controller_client::get_instance();
    ctf_ca_cancel_in_chip_task(); /* a signer's late answer must not reach CHIP */
    if (c.get_commissioner()) {
        LogErrorOnFailure(c.get_commissioner()->StopPairing((chip::NodeId)node));
        /* A pairing stopped before PASE (the device wasn't found) reports nothing,
         * so its delegate would stay registered and refuse the next one. */
        c.get_commissioner()->RegisterPairingDelegate(nullptr);
    }
    ctf_ctl_icd_abort_in_chip_task(node);
    finish((uint32_t)gen, timed_out(OP_COMMISSION, node));
}

/* CHIP gave up on the code: no device found, or none took it (CHIP thread, after
 * CHIP's own callbacks). One that got as far as PASE has been answered by on_pase
 * already; for none found CHIP reports nothing else, so answer here rather than
 * at the watchdog. */
static void pairing_failed_in_chip_task(intptr_t gen)
{
    const op_t op = current();
    if (op.kind != OP_COMMISSION || op.gen != (uint32_t)gen || op.stopping) return;
    auto *commissioner = matter_controller_client::get_instance().get_commissioner();
    if (commissioner) commissioner->RegisterPairingDelegate(nullptr); /* else it refuses the next one */
    ctf_ctl_icd_abort_in_chip_task(op.node);
    finish(op.gen, ctf_result_err("not_found", "no device answered this code, over Bluetooth or on the network"));
}

void ctf_ctl_pairing_failed(void)
{
    const op_t op = current();
    if (op.kind == OP_COMMISSION) schedule(pairing_failed_in_chip_task, (intptr_t)op.gen);
}

static void stop_discovery_in_chip_task(intptr_t)
{
    auto *commissioner = matter_controller_client::get_instance().get_commissioner();
    if (commissioner) LogErrorOnFailure(commissioner->StopCommissionableDiscovery());
}

static void watchdog_fired(void *arg)
{
    (void)arg;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint32_t gen = s_op.gen;
    op_kind_t kind = s_op.kind;
    uint64_t node = s_op.node;
    if (kind == OP_COMMISSION) s_op.stopping = true;
    xSemaphoreGive(s_lock);
    if (kind == OP_NONE) return;
    if (kind == OP_COMMISSION && schedule(stop_pairing_in_chip_task, (intptr_t)gen)) {
        return; /* it answers */
    }
    if (kind == OP_DISCOVER) schedule(stop_discovery_in_chip_task, 0);
    finish(gen, timed_out(kind, node));
}

static cJSON *err_chip(const char *code, const char *what, CHIP_ERROR e)
{
    return ctf_result_err(code, "%s: %s", what, e.AsString());
}

/* ---- node list (NVS) ---------------------------------------------------- */

/* The list is JSON in an NVS blob ("nodes"), at most MAX_NODES devices. Its
 * read-modify-write paths hold s_nodes_lock (commands and CHIP callbacks run
 * on different tasks). */
static SemaphoreHandle_t s_nodes_lock;

static void nodes_lock(void) { xSemaphoreTake(s_nodes_lock, portMAX_DELAY); }

static void nodes_unlock(void) { xSemaphoreGive(s_nodes_lock); }

static char *nodes_read(nvs_handle_t h)
{
    size_t n = 0;
    esp_err_t err = nvs_get_blob(h, "nodes", NULL, &n);
    if (err != ESP_OK || n <= 1) return NULL;
    char *s = (char *)malloc(n + 1);
    if (!s) return NULL;
    err = nvs_get_blob(h, "nodes", s, &n);
    if (err != ESP_OK) {
        free(s);
        return NULL;
    }
    s[n] = 0;
    return s;
}

static cJSON *nodes_load(void)
{
    nvs_handle_t h;
    cJSON *arr = NULL;
    if (ctf_nvs_open(NVS_READONLY, &h) == ESP_OK) {
        char *s = nodes_read(h);
        if (s) arr = cJSON_Parse(s);
        free(s);
        nvs_close(h);
    }
    return cJSON_IsArray(arr) ? arr : (cJSON_Delete(arr), cJSON_CreateArray());
}

static esp_err_t nodes_save(cJSON *arr)
{
    char *s = cJSON_PrintUnformatted(arr);
    if (!s) return ESP_ERR_NO_MEM;
    nvs_handle_t h;
    esp_err_t err = ctf_nvs_open(NVS_READWRITE, &h);
    if (err == ESP_OK) {
        err = nvs_set_blob(h, "nodes", s, strlen(s));
        if (err == ESP_OK) err = nvs_commit(h);
        nvs_close(h);
    }
    cJSON_free(s);
    return err;
}

static int nodes_find(cJSON *arr, uint64_t id)
{
    for (int i = 0; i < cJSON_GetArraySize(arr); i++) {
        cJSON *n = cJSON_GetObjectItem(cJSON_GetArrayItem(arr, i), "node_id");
        if (cJSON_IsNumber(n) && (uint64_t)n->valuedouble == id) return i;
    }
    return -1;
}

static esp_err_t nodes_put(uint64_t id, const char *label)
{
    nodes_lock();
    cJSON *arr = nodes_load();
    int i = nodes_find(arr, id);
    if (i >= 0) cJSON_DeleteItemFromArray(arr, i);
    esp_err_t err = ESP_ERR_NO_MEM;
    if (cJSON_GetArraySize(arr) < MAX_NODES) { /* commission_cmd refuses a full list */
        cJSON *n = cJSON_CreateObject();
        cJSON_AddNumberToObject(n, "node_id", (double)id);
        if (label && *label) cJSON_AddStringToObject(n, "label", label);
        cJSON_AddItemToArray(arr, n);
        err = nodes_save(arr);
    }
    cJSON_Delete(arr);
    nodes_unlock();
    return err;
}

/* Give a listed node a new label ("" removes it); ESP_ERR_NOT_FOUND if it isn't listed. */
static esp_err_t nodes_set_label(uint64_t id, const char *label)
{
    nodes_lock();
    cJSON *arr = nodes_load();
    int i = nodes_find(arr, id);
    esp_err_t err = ESP_ERR_NOT_FOUND;
    if (i >= 0) {
        cJSON *n = cJSON_GetArrayItem(arr, i);
        cJSON_DeleteItemFromObject(n, "label");
        if (*label) cJSON_AddStringToObject(n, "label", label);
        err = nodes_save(arr);
    }
    cJSON_Delete(arr);
    nodes_unlock();
    return err;
}

/* The forwarder's own sessions with a node that left (CHIP thread). */
static void release_node_in_chip_task(intptr_t arg)
{
    const uint64_t node = ctf_ctl_take_node(arg);
    auto *c = matter_controller_client::get_instance().get_commissioner();
    if (!c) return;
    const ScopedNodeId peer((chip::NodeId)node, c->GetFabricIndex());
    if (c->CASESessionMgr()) c->CASESessionMgr()->ReleaseSession(peer);
    c->SessionMgr()->ExpireAllSessions(peer);
}

static void nodes_drop(uint64_t id)
{
    nodes_lock();
    cJSON *arr = nodes_load();
    int i = nodes_find(arr, id);
    if (i >= 0) {
        cJSON_DeleteItemFromArray(arr, i);
        nodes_save(arr);
    }
    cJSON_Delete(arr);
    nodes_unlock();
    ctf_ctl_icd_forget(id);
    if (!ctf_ctl_schedule_node(release_node_in_chip_task, id)) {
        ESP_LOGW(TAG, "node %llu: its sessions stay until they expire", (unsigned long long)id);
    }
}

static int nodes_count(void)
{
    cJSON *arr = nodes_load();
    int n = cJSON_GetArraySize(arr);
    cJSON_Delete(arr);
    return n;
}

bool ctf_ctl_started(void) { return s_started; }

extern "C" bool ctf_ctl_node_known(uint64_t node_id)
{
    cJSON *arr = nodes_load();
    bool known = nodes_find(arr, node_id) >= 0;
    cJSON_Delete(arr);
    return known;
}

/* Node IDs are never reused: a Matter device's operational DNS-SD name is
 * <fabric>-<node id>, and a Thread Border Router's SRP server keeps a name
 * reserved for its first owner's key lease (days) even after the device is
 * removed or reset, so a second device given the same ID can't register it
 * and is never found. A persistent counter, from kFirstNodeId; an ID the
 * caller chose (want) moves it past that one, so it isn't handed out again. */
static uint64_t nodes_alloc_id(uint64_t want)
{
    nvs_handle_t h;
    if (ctf_nvs_open(NVS_READWRITE, &h) != ESP_OK) return want ? want : kFirstNodeId + (esp_random() % 100000);
    nodes_lock();
    uint32_t next = kFirstNodeId;
    nvs_get_u32(h, "next_id", &next);
    uint64_t id = want;
    if (!id) {
        cJSON *arr = nodes_load();
        while (nodes_find(arr, next) >= 0) next++;
        cJSON_Delete(arr);
        id = next;
    }
    if (id >= next && id < UINT32_MAX) {
        nvs_set_u32(h, "next_id", (uint32_t)id + 1);
        nvs_commit(h);
    }
    nodes_unlock();
    nvs_close(h);
    return id;
}

/* ---- commissioning -------------------------------------------------------- */

typedef struct {
    uint32_t gen;
    uint64_t node;
    char code[128];
    char ssid[33];
    char password[65];
    uint8_t dataset[CTF_THREAD_DATASET_MAX];
    size_t dataset_len;
    bool use_wifi, use_thread;
} commission_job_t;

/* The job holds a Wi-Fi password and a Thread dataset: wiped before it's freed. */
static void job_free(commission_job_t *j)
{
    memset(j, 0, sizeof(*j));
    free(j);
}

static void on_pase(CHIP_ERROR err)
{
    ESP_LOGI(TAG, "PASE: %s", err == CHIP_NO_ERROR ? "established" : err.AsString());
    if (err == CHIP_NO_ERROR) return;
    /* No secure session with the device (a wrong code, or it left pairing
     * mode): answer now rather than at the watchdog. */
    const op_t op = current();
    if (op.kind == OP_COMMISSION && !op.stopping) {
        finish(op.gen, err_chip("commissioning_failed", "no secure session with the device (PASE)", err));
    }
}

static void on_commission_ok(ScopedNodeId peer)
{
    const op_t op = current();
    if (op.kind != OP_COMMISSION || op.node != peer.GetNodeId()) return;
    const double secs = (esp_timer_get_time() - op.t0_us) / 1e6;
    if (nodes_put(peer.GetNodeId(), op.label) != ESP_OK) {
        finish(op.gen, ctf_result_err("nvs", "node %llu is commissioned but could not be stored; remove it (forget) and add it again",
                                     (unsigned long long)peer.GetNodeId()));
        return;
    }
    cJSON *p = node_payload(peer.GetNodeId());
    cJSON_AddNumberToObject(p, "seconds", (int)(secs * 10) / 10.0);
    if (ctf_ctl_icd_take_store_failure()) {
        cJSON_AddStringToObject(p, "warning", "a sleepy device whose check-in key could not be stored: its check-ins will "
                                              "be missed; remove it and add it again");
    }
    finish(op.gen, ctf_result_ok(p));
}

static void on_commission_fail(ScopedNodeId peer, CHIP_ERROR error, chip::Controller::CommissioningStage stage,
                               std::optional<chip::Credentials::AttestationVerificationResult> att)
{
    const op_t op = current();
    if (op.kind != OP_COMMISSION || op.stopping || op.node != peer.GetNodeId()) return;
    char extra[48] = "";
    if (att.has_value()) snprintf(extra, sizeof(extra), " (attestation %d)", (int)att.value());
    finish(op.gen, ctf_result_err("commissioning_failed", "stage %s: %s%s", chip::Controller::StageToString(stage),
                              error.AsString(), extra));
}

static void on_unpair(chip::NodeId node, CHIP_ERROR err)
{
    const op_t op = current();
    if (op.kind != OP_REMOVE || op.node != node) return;
    if (err != CHIP_NO_ERROR) {
        finish(op.gen, err_chip("remove_failed", "the device did not leave the fabric", err));
        return;
    }
    nodes_drop(node);
    finish(op.gen, ctf_result_ok(node_payload(node)));
}

/* esp-matter's pairing_code*() with this controller's ICD registration (a key
 * per device), and CHIP's refusal reported instead of only logged. */
static void commission_in_chip_task(intptr_t arg)
{
    commission_job_t *j = (commission_job_t *)arg;
    auto *commissioner = matter_controller_client::get_instance().get_commissioner();
    CHIP_ERROR err = CHIP_ERROR_INCORRECT_STATE;
    if (commissioner && !commissioner->GetPairingDelegate()) {
        chip::Controller::CommissioningParameters params;
        if (j->use_wifi) {
            params.SetWiFiCredentials(chip::Controller::WiFiCredentials(
                chip::ByteSpan((const uint8_t *)j->ssid, strlen(j->ssid)),
                chip::ByteSpan((const uint8_t *)j->password, strlen(j->password))));
        }
        if (j->use_thread) params.SetThreadOperationalDataset(chip::ByteSpan(j->dataset, j->dataset_len));
        chip::Controller::DevicePairingDelegate *delegate = ctf_ctl_icd_prepare_commission(params);
        if (delegate) {
            commissioner->RegisterPairingDelegate(delegate);
            const auto discovery = j->use_wifi || j->use_thread ? chip::Controller::DiscoveryType::kAll
                                                                : chip::Controller::DiscoveryType::kDiscoveryNetworkOnly;
            err = commissioner->PairDevice(j->node, j->code, params, discovery);
            if (err != CHIP_NO_ERROR) commissioner->RegisterPairingDelegate(nullptr);
        } else {
            err = CHIP_ERROR_INTERNAL; /* no random ICD key */
        }
    }
    if (err != CHIP_NO_ERROR) finish(j->gen, err_chip("commissioning_failed", "could not start", err));
    job_free(j);
}

cJSON *ctf_ctl_not_started(void)
{
    return ctf_result_err("matter_unavailable", "the Matter controller is not running%s%s", s_start_error[0] ? ": " : "",
                         s_start_error);
}

static cJSON *commission_cmd(const cJSON *params, ctf_reply_t *reply)
{
    if (!s_started) return ctf_ctl_not_started();
    /* The calling cloud controller verifies and signs every device (forwarder_ca). */
    if (!ctf_ca_enrolled()) {
        return ctf_result_err("not_enrolled", "enroll this forwarder first: chip-tool-remote forwarder call matter.enroll (the "
                                             "fabric's CA is the cloud controller's)");
    }
    const char *code = ctf_param_str(params, "code", "");
    if (!(strncmp(code, "MT:", 3) == 0 || (strspn(code, "0123456789- ") == strlen(code) && strlen(code) >= 11))) {
        return ctf_result_err("invalid_param", "code must be the QR text (MT:...) or the 11/21-digit manual code");
    }
    if (strlen(ctf_param_str(params, "label", "")) > MAX_LABEL) return label_too_long();
    const char *network = ctf_param_str(params, "network", "auto");
    if (strcmp(network, "auto") && strcmp(network, "wifi") && strcmp(network, "thread") && strcmp(network, "none")) {
        return ctf_result_err("invalid_param", "network must be auto, wifi, thread or none");
    }
    if (nodes_count() >= MAX_NODES) {
        return ctf_result_err("full", "the forwarder holds %d devices already; remove one first", MAX_NODES);
    }
    long long want = ctf_param_int(params, "node_id", 0);
    if (want != 0) {
        if (want < 1 || !chip::IsOperationalNodeId((chip::NodeId)want) || (uint64_t)want > (1ULL << 53) ||
            (uint64_t)want == kControllerNodeId) {
            return ctf_result_err("invalid_param", "node_id must be an operational node ID, not the controller's");
        }
        if (ctf_ctl_node_known((uint64_t)want)) {
            return ctf_result_err("invalid_param", "node %lld is in the list already", want);
        }
    }
    const char *ssid = ctf_param_str(params, "wifi_ssid", NULL);
    const char *pass = ctf_param_str(params, "wifi_password", "");
    if (ssid && (strlen(ssid) > 32 || strlen(pass) > 64)) {
        return ctf_result_err("invalid_param", "wifi_ssid is at most 32 bytes and wifi_password at most 64");
    }
    if (strlen(code) >= sizeof(((commission_job_t *)0)->code)) {
        return ctf_result_err("invalid_param", "code is too long");
    }
    commission_job_t *j = (commission_job_t *)calloc(1, sizeof(*j));
    if (!j) return ctf_result_err("out_of_memory", "no memory");
    snprintf(j->code, sizeof(j->code), "%s", code);

    /* Wi-Fi: given, or the network this device is on. */
    if (ssid) {
        snprintf(j->ssid, sizeof(j->ssid), "%s", ssid);
        snprintf(j->password, sizeof(j->password), "%s", pass);
    } else {
        wifi_config_t cfg = {};
        if (esp_wifi_get_config(WIFI_IF_STA, &cfg) == ESP_OK && cfg.sta.ssid[0]) {
            memcpy(j->ssid, cfg.sta.ssid, sizeof(cfg.sta.ssid));
            memcpy(j->password, cfg.sta.password, sizeof(cfg.sta.password));
        }
        memset(&cfg, 0, sizeof(cfg));
    }
    /* Thread: given, or the stored dataset. */
    const char *ds = ctf_param_str(params, "thread_dataset", NULL);
    if (ds) {
        int n = ctf_thread_hex_decode(ds, j->dataset, sizeof(j->dataset));
        const char *why = n > 0 ? ctf_thread_dataset_check(j->dataset, (size_t)n, NULL) : "not hex";
        if (why) {
            job_free(j);
            return ctf_result_err("invalid_param", "thread_dataset: %s", why);
        }
        j->dataset_len = (size_t)n;
    } else {
        j->dataset_len = sizeof(j->dataset);
        if (!ctf_thread_dataset_get(j->dataset, &j->dataset_len)) j->dataset_len = 0;
    }
    bool auto_ = strcmp(network, "auto") == 0;
    j->use_wifi = (auto_ || strcmp(network, "wifi") == 0) && j->ssid[0];
    j->use_thread = (auto_ || strcmp(network, "thread") == 0) && j->dataset_len;
    if (strcmp(network, "wifi") == 0 && !j->use_wifi) {
        job_free(j);
        return ctf_result_err("invalid_param", "no Wi-Fi network: give wifi_ssid/wifi_password");
    }
    if (strcmp(network, "thread") == 0 && !j->use_thread) {
        job_free(j);
        return ctf_result_err("invalid_param", "no Thread dataset: thread.set_dataset first, or give thread_dataset");
    }
    if (!begin(OP_COMMISSION, reply, 0, kCommissionMs, &j->gen)) {
        job_free(j);
        return ctf_result_err("busy", "another Matter operation is running");
    }
    /* Only now, so that a refused request doesn't use up a node ID. */
    j->node = nodes_alloc_id(want > 0 ? (uint64_t)want : 0);
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_op.node = j->node;
    snprintf(s_op.label, sizeof(s_op.label), "%s", ctf_param_str(params, "label", ""));
    xSemaphoreGive(s_lock);
    /* The cloud controller that asked verifies and signs for this one (forwarder_ca). */
    ctf_ca_set_signer_conn(ctf::CurrentCallConnection());
    ESP_LOGI(TAG, "commissioning node %llu (wifi %s, thread %s)", (unsigned long long)j->node,
             j->use_wifi ? "yes" : "no", j->use_thread ? "yes" : "no");
    uint32_t gen = j->gen;
    if (!schedule(commission_in_chip_task, (intptr_t)j)) {
        job_free(j);
        finish(gen, no_chip_thread());
    }
    return CTF_ASYNC;
}

/* ---- remove, open_window, nodes, status --------------------------------- */

static void remove_in_chip_task(intptr_t arg)
{
    const uint64_t node = ctf_ctl_take_node(arg);
    if (unpair_device((chip::NodeId)node) != ESP_OK) {
        const op_t op = current();
        if (op.kind == OP_REMOVE) finish(op.gen, ctf_result_err("remove_failed", "could not start removing the device"));
    }
}

static cJSON *remove_cmd(const cJSON *params, ctf_reply_t *reply)
{
    uint64_t node = (uint64_t)ctf_param_int(params, "node_id", 0);
    if (!ctf_ctl_node_known(node)) return ctf_ctl_unknown_node(node);
    if (ctf_param_bool(params, "forget", false)) {
        /* A device that was reset or is gone can't leave the fabric itself. */
        nodes_drop(node);
        cJSON *p = node_payload(node);
        cJSON_AddBoolToObject(p, "forgotten", true);
        return ctf_result_ok(p);
    }
    if (!s_started) return ctf_ctl_not_started();
    uint32_t gen;
    if (!begin(OP_REMOVE, reply, node, kOperationMs, &gen)) return ctf_result_err("busy", "another Matter operation is running");
    if (!ctf_ctl_schedule_node(remove_in_chip_task, node)) finish(gen, no_chip_thread());
    return CTF_ASYNC;
}

static void on_window_open(const char *manual_code)
{
    const op_t op = current();
    if (op.kind != OP_WINDOW) return;
    cJSON *p = node_payload(op.node);
    cJSON_AddStringToObject(p, "manual_code", manual_code);
    finish(op.gen, ctf_result_ok(p));
}

typedef struct {
    uint64_t node;
    uint16_t timeout_s;
} window_job_t;

static void window_in_chip_task(intptr_t arg)
{
    window_job_t *j = (window_job_t *)arg;
    uint16_t disc = (uint16_t)(esp_random() & kDiscriminatorMask);
    esp_err_t err = commissioning_window_opener::get_instance().send_open_commissioning_window_command(
        j->node, true, j->timeout_s, kWindowPbkdfIterations, disc, kWindowTimedInvokeMs);
    if (err != ESP_OK) {
        const op_t op = current();
        if (op.kind == OP_WINDOW) finish(op.gen, ctf_result_err("window_failed", "could not open a commissioning window"));
    }
    free(j);
}

static cJSON *window_cmd(const cJSON *params, ctf_reply_t *reply)
{
    if (!s_started) return ctf_ctl_not_started();
    uint64_t node = (uint64_t)ctf_param_int(params, "node_id", 0);
    if (!ctf_ctl_node_known(node)) return ctf_ctl_unknown_node(node);
    window_job_t *j = (window_job_t *)calloc(1, sizeof(*j));
    if (!j) return ctf_result_err("out_of_memory", "no memory");
    j->node = node;
    long long t = ctf_param_int(params, "timeout_s", kWindowDefaultS);
    j->timeout_s = (uint16_t)(t < kWindowMinS ? kWindowMinS : t > kWindowMaxS ? kWindowMaxS : t);
    uint32_t gen;
    if (!begin(OP_WINDOW, reply, j->node, kOperationMs, &gen)) {
        free(j);
        return ctf_result_err("busy", "another Matter operation is running");
    }
    if (!schedule(window_in_chip_task, (intptr_t)j)) {
        free(j);
        finish(gen, no_chip_thread());
    }
    return CTF_ASYNC;
}

/* ---- commissionables ----------------------------------------------------- */

/* Devices in a commissioning window advertise "_matterc._udp" (DNS-SD): a
 * Wi-Fi device directly, a Thread device through the home's border router.
 * The commissioner keeps the first CHIP_DEVICE_CONFIG_MAX_DISCOVERED_NODES. */
static esp_timer_handle_t s_discover_timer;

static void discover_done_in_chip_task(intptr_t arg)
{
    const uint32_t gen = (uint32_t)arg;
    const op_t op = current();
    if (op.kind != OP_DISCOVER || op.gen != gen) return;
    auto *commissioner = matter_controller_client::get_instance().get_commissioner();
    cJSON *devices = cJSON_CreateArray();
    for (int i = 0; commissioner && i < CHIP_DEVICE_CONFIG_MAX_DISCOVERED_NODES; i++) {
        const chip::Dnssd::CommissionNodeData *node = commissioner->GetDiscoveredDevice(i);
        if (!node) continue;
        cJSON *device = cJSON_CreateObject();
        /* How it was found: "network" (DNS-SD); Bluetooth may be added later. */
        cJSON_AddStringToObject(device, "via", "network");
        cJSON_AddNumberToObject(device, "vendor_id", node->vendorId);
        cJSON_AddNumberToObject(device, "product_id", node->productId);
        cJSON_AddNumberToObject(device, "discriminator", node->longDiscriminator);
        /* 1: the device's own window (its setup code works); 2: one opened by
         * another app, with the code that app shows. */
        cJSON_AddNumberToObject(device, "commissioning_mode", node->commissioningMode);
        if (node->deviceType) cJSON_AddNumberToObject(device, "device_type", node->deviceType);
        if (node->deviceName[0]) cJSON_AddStringToObject(device, "name", node->deviceName);
        if (node->pairingHint) cJSON_AddNumberToObject(device, "pairing_hint", node->pairingHint);
        if (node->pairingInstruction[0]) cJSON_AddStringToObject(device, "pairing_instruction", node->pairingInstruction);
        cJSON_AddStringToObject(device, "instance", node->instanceName);
        cJSON_AddItemToArray(devices, device);
    }
    if (commissioner) LogErrorOnFailure(commissioner->StopCommissionableDiscovery());
    cJSON *payload = cJSON_CreateObject();
    cJSON_AddItemToObject(payload, "devices", devices);
    finish(gen, ctf_result_ok(payload));
}

static void discover_timer_fired(void *arg)
{
    if (!schedule(discover_done_in_chip_task, (intptr_t)arg)) finish((uint32_t)(intptr_t)arg, no_chip_thread());
}

typedef struct {
    uint32_t gen;
    uint32_t seconds;
} discover_job_t;

static void discover_in_chip_task(intptr_t arg)
{
    const discover_job_t job = *(discover_job_t *)arg;
    free((void *)arg);
    auto *commissioner = matter_controller_client::get_instance().get_commissioner();
    CHIP_ERROR err = commissioner ? commissioner->DiscoverCommissionableNodes(chip::Dnssd::DiscoveryFilter())
                                  : CHIP_ERROR_INCORRECT_STATE;
    if (err != CHIP_NO_ERROR) {
        finish(job.gen, err_chip("discover_failed", "could not browse for devices", err));
        return;
    }
    if (s_discover_timer) {
        esp_timer_stop(s_discover_timer);
        esp_timer_delete(s_discover_timer);
        s_discover_timer = nullptr;
    }
    const esp_timer_create_args_t args = {.callback = discover_timer_fired, .arg = (void *)(intptr_t)job.gen,
                                          .dispatch_method = ESP_TIMER_TASK, .name = "ctf_discovery",
                                          .skip_unhandled_events = true};
    if (esp_timer_create(&args, &s_discover_timer) != ESP_OK ||
        esp_timer_start_once(s_discover_timer, (uint64_t)job.seconds * 1000 * 1000) != ESP_OK) {
        LogErrorOnFailure(commissioner->StopCommissionableDiscovery());
        finish(job.gen, ctf_result_err("internal", "could not time the discovery"));
    }
}

static cJSON *discover_cmd(const cJSON *params, ctf_reply_t *reply)
{
    if (!s_started) return ctf_ctl_not_started();
    long long t = ctf_param_int(params, "timeout_s", kDiscoverDefaultS);
    discover_job_t *j = (discover_job_t *)calloc(1, sizeof(*j));
    if (!j) return ctf_result_err("out_of_memory", "no memory");
    j->seconds = (uint32_t)(t < 1 ? 1 : t > kDiscoverMaxS ? kDiscoverMaxS : t);
    if (!begin(OP_DISCOVER, reply, 0, j->seconds * 1000 + 10000, &j->gen)) {
        free(j);
        return ctf_result_err("busy", "another Matter operation is running");
    }
    const uint32_t gen = j->gen;
    if (!schedule(discover_in_chip_task, (intptr_t)j)) {
        free(j);
        finish(gen, no_chip_thread());
    }
    return CTF_ASYNC;
}

static cJSON *nodes_cmd(const cJSON *, ctf_reply_t *)
{
    cJSON *p = cJSON_CreateObject();
    cJSON_AddItemToObject(p, "nodes", nodes_load());
    return ctf_result_ok(p);
}

static cJSON *rename_cmd(const cJSON *params, ctf_reply_t *)
{
    uint64_t node = (uint64_t)ctf_param_int(params, "node_id", 0);
    const char *label = ctf_param_str(params, "label", "");
    if (strlen(label) > MAX_LABEL) return label_too_long();
    esp_err_t err = nodes_set_label(node, label);
    if (err == ESP_ERR_NOT_FOUND) return ctf_ctl_unknown_node(node);
    if (err != ESP_OK) return ctf_result_err("nvs", "the label could not be stored: %s", esp_err_to_name(err));
    cJSON *p = node_payload(node);
    if (*label) cJSON_AddStringToObject(p, "label", label);
    return ctf_result_ok(p);
}


/* ---- start ------------------------------------------------------------------ */

static void on_matter_event(const chip::DeviceLayer::ChipDeviceEvent *event, intptr_t)
{
    if (event->Type == chip::DeviceLayer::DeviceEventType::kInterfaceIpAddressChanged) {
        ESP_LOGI(TAG, "interface address changed");
        ctf_ctl_install_queue_filter(); /* after ESP's own, which it re-installs on IPv6 events */
    }
}

static void controller_setup_in_chip_task(intptr_t)
{
    using chip::DeviceLayer::ConnectivityManager;
    /* The firmware owns Wi-Fi (provisioning, known networks, reconnects):
     * CHIP only watches the station. */
    LogErrorOnFailure(chip::DeviceLayer::ConnectivityMgr().SetWiFiStationMode(ConnectivityManager::kWiFiStationMode_ApplicationControlled));
    ctf_ctl_install_queue_filter();
    auto &client = matter_controller_client::get_instance();
    esp_err_t err = client.init(kControllerNodeId, kFabricId, kListenPort);
    if (err == ESP_OK) err = client.setup_commissioner();
    if (err != ESP_OK) {
        snprintf(s_start_error, sizeof(s_start_error), "commissioner setup failed: %s", esp_err_to_name(err));
        ESP_LOGE(TAG, "%s", s_start_error);
        return;
    }
    pairing_command::get_instance().set_callbacks({on_pase, on_commission_ok, on_commission_fail, on_unpair});
    commissioning_window_opener::get_instance().set_callback(on_window_open);
    ctf_ctl_icd_setup_in_chip_task();
    s_started = true;
    ESP_LOGI(TAG, "Matter controller running: fabric %llu, node %llu", (unsigned long long)kFabricId,
             (unsigned long long)kControllerNodeId);
}

/* Only on a boot after setup: until then BLE belongs to the application's setup. */
extern "C" void ctf_ctl_start(void)
{
    esp_err_t err = esp_matter::start(on_matter_event);
    if (err != ESP_OK) {
        snprintf(s_start_error, sizeof(s_start_error), "esp_matter::start: %s", esp_err_to_name(err));
        ESP_LOGE(TAG, "%s", s_start_error);
        return;
    }
    if (!schedule(controller_setup_in_chip_task, 0)) ESP_LOGE(TAG, "could not reach the Matter thread");
}

/* ---- registration ------------------------------------------------------- */

/* code: the device's Matter setup code, QR text (MT:...) or the 11/21-digit
 * manual code. node_id: the ID to give it (default: a new one; IDs are never
 * reused). network: auto (default: Wi-Fi or Thread, as the device supports),
 * wifi, thread, or none (already on the network, e.g. a code shared from
 * another app). wifi_ssid/wifi_password: the Wi-Fi for the device (default:
 * the network this forwarder is on). thread_dataset: hex (default: the stored
 * one). label: a name to remember the device by, at most MAX_LABEL bytes. */
static const ctf_param_t commission_req[] = {{"code", CTF_PARAM_STRING}};
static const ctf_param_t commission_opt[] = {
    {"node_id", CTF_PARAM_INTEGER},     {"network", CTF_PARAM_STRING},        {"wifi_ssid", CTF_PARAM_STRING},
    {"wifi_password", CTF_PARAM_STRING}, {"thread_dataset", CTF_PARAM_STRING}, {"label", CTF_PARAM_STRING},
};
static const ctf_param_t node_req[] = {{"node_id", CTF_PARAM_INTEGER}}; /* see matter.nodes */
/* forget: only drop it from the list (the device was reset or is gone). */
static const ctf_param_t remove_opt[] = {{"forget", CTF_PARAM_BOOLEAN}};
/* label: the new one, at most MAX_LABEL bytes ("" removes it). */
static const ctf_param_t rename_req[] = {{"node_id", CTF_PARAM_INTEGER}, {"label", CTF_PARAM_STRING}};
/* timeout_s: how long the window stays open, 180-900 s (default 300). */
static const ctf_param_t window_opt[] = {{"timeout_s", CTF_PARAM_INTEGER}};
/* timeout_s: how long to listen, 1-15 s (default 4). */
static const ctf_param_t discover_opt[] = {{"timeout_s", CTF_PARAM_INTEGER}};

static const ctf_cmd_def_t s_cmds[] = {
    /* Add a Matter device (Wi-Fi or Thread) to this home's fabric from its
     * setup code. New devices are reached over Bluetooth by this forwarder and
     * given the home's network; devices already on the network (a code shared
     * from another app) are found on it. Returns the node ID. */
    {.name = "matter.commission",
     .required = commission_req,
     .n_required = 1,
     .optional = commission_opt,
     .n_optional = 6,
     .timeout_ms = kCommissionMs,
     .fn = commission_cmd},
    /* The devices this forwarder commissioned (node ID, label). */
    {.name = "matter.nodes", .fn = nodes_cmd},
    /* Change a device's label in this forwarder's list. The device's own name
     * (Basic Information NodeLabel, which every app it's shared with reads)
     * doesn't change. */
    {.name = "matter.rename", .required = rename_req, .n_required = 2, .fn = rename_cmd},
    /* Devices in pairing mode on the network (their own window, or one another
     * app opened), found by this forwarder: what matter.commission can add. */
    {.name = "matter.commissionables",
     .optional = discover_opt,
     .n_optional = 1,
     .timeout_ms = (uint32_t)(kDiscoverMaxS + 20) * 1000,
     .fn = discover_cmd},
    /* Remove a device from this home's fabric (it leaves the fabric; other
     * apps keep theirs). forget=true only drops it from the list. */
    {.name = "matter.remove",
     .required = node_req,
     .n_required = 1,
     .optional = remove_opt,
     .n_optional = 1,
     .timeout_ms = kOperationMs,
     .fn = remove_cmd},
    /* Open a commissioning window on a device so another app or ecosystem can
     * add it too. Returns the manual pairing code to enter there. */
    {.name = "matter.open_window",
     .required = node_req,
     .n_required = 1,
     .optional = window_opt,
     .n_optional = 1,
     .timeout_ms = kOperationMs,
     .fn = window_cmd},
};

extern "C" void ctf_ctl_register(void)
{
    static StaticSemaphore_t lock_buf;
    s_lock = xSemaphoreCreateMutexStatic(&lock_buf);
    static StaticSemaphore_t nodes_lock_buf;
    s_nodes_lock = xSemaphoreCreateMutexStatic(&nodes_lock_buf);
    const esp_timer_create_args_t args = {.callback = watchdog_fired, .arg = NULL, .dispatch_method = ESP_TIMER_TASK,
                                          .name = "ctf_watchdog", .skip_unhandled_events = true};
    esp_timer_create(&args, &s_watchdog);
    for (size_t i = 0; i < sizeof(s_cmds) / sizeof(s_cmds[0]); i++) ctf_cmd_register(&s_cmds[i]);
    ctf_ctl_icd_register();
}
