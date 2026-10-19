// SPDX-License-Identifier: Apache-2.0

// The forwarder: the stream server and relay (core/), the commands a cloud
// controller calls over it, and matter.connect; see forwarder.h.
#include "forwarder.h"

#include <atomic>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "ctf_cmd.h"
#include "controller.h"
#include "forwarder_ca.h"
#include "forwarder_secret.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"

#include <controller/CHIPDeviceControllerFactory.h>
#include <esp_matter_controller_client.h>
#include <platform/CHIPDeviceLayer.h>

#include "ctf_relay.h"
#include "ctf_server.h"

#define TAG "ctf"

namespace {

constexpr uint16_t kPort = ctf::kDefaultPort;
constexpr size_t kTaskStack  = 4096; // start, the netif listener
constexpr size_t kEventStack = 6144; // each event is a TLS write to every connection (Xtensa needs the room)

bool s_started;
uint16_t s_chip_port;

struct Spawn
{
    void (*fn)(void *);
    void * arg;
    bool psram;
};

void task_main(void * p)
{
    Spawn s = *static_cast<Spawn *>(p);
    delete static_cast<Spawn *>(p);
    s.fn(s.arg);
    if (s.psram)
    {
        vTaskDeleteWithCaps(NULL);
    }
    else
    {
        vTaskDelete(NULL);
    }
}

// A task that may write flash (a forwarder command: NVS) needs its stack in
// internal RAM: while flash is written the cache PSRAM sits behind is off.
// (reads too). The listener and the connections never do: stacks in PSRAM.
bool needs_internal_stack(const char * name)
{
    return strcmp(name, "ctf_call") == 0 || strcmp(name, "ctf_start") == 0; // init reads NVS
}

bool spawn(void (*fn)(void *), void * arg, const char * name, size_t stack)
{
    Spawn * s = new (std::nothrow) Spawn{ fn, arg, !needs_internal_stack(name) };
    BaseType_t ok = pdFAIL;
    if (s != nullptr)
    {
        if (s->psram)
        {
            ok = xTaskCreateWithCaps(task_main, name, stack, s, 4, NULL, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        }
        if (ok != pdPASS) // PSRAM is full: internal RAM
        {
            s->psram = false;
            ok       = xTaskCreate(task_main, name, stack, s, 4, NULL);
        }
    }
    if (ok != pdPASS)
    {
        ESP_LOGE(TAG, "can't start task %s", name);
        delete s;
        return false;
    }
    return true;
}

void * psram_alloc(size_t n)
{
    void * p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    return p ? p : malloc(n);
}

void psram_release(void * p)
{
    heap_caps_free(p);
}

bool node_allowed(chip::NodeId node)
{
    return ctf_ctl_node_known(node);
}

/* ---- forwarder commands over the stream (ctf_proto.h call/result) ---------- */

// A cloud controller may call every command registered in ctf_cmd
// (commissioning, the node list, sleepy devices, the Thread dataset,
// enrollment, status). chip_tool_forwarder_connect() isn't one: it hands out
// the secret, so only the application's own channel offers it.

struct CallWait
{
    SemaphoreHandle_t done;
    cJSON * result;
    std::atomic<int> refs{ 2 }; // the caller and the reply sink
};

void call_wait_release(CallWait * w)
{
    if (w->refs.fetch_sub(1) == 1)
    {
        cJSON_Delete(w->result);
        vSemaphoreDelete(w->done);
        delete w;
    }
}

void call_sink(void * ctx, cJSON * result)
{
    auto * w  = static_cast<CallWait *>(ctx);
    w->result = result;
    xSemaphoreGive(w->done);
    call_wait_release(w);
}

void write_result(cJSON * result, char * out, size_t cap)
{
    if (result == nullptr || !cJSON_PrintPreallocated(result, out, static_cast<int>(cap), false))
    {
        snprintf(out, cap, "{\"ok\":false,\"error\":{\"code\":\"too_large\",\"message\":\"result over %u bytes\"}}",
                 static_cast<unsigned>(cap));
    }
}

void call_cmd(const char * name, const char * params, char * out, size_t cap)
{
    const ctf_cmd_def_t * def = ctf_cmd_find(name);
    if (def == nullptr)
    {
        // Name the commands, so a caller with an old name finds the new one.
        char names[320];
        ctf_cmd_names(names, sizeof(names));
        snprintf(out, cap, "{\"ok\":false,\"error\":{\"code\":\"unknown_command\",\"message\":\"no forwarder command %s; the commands are %s\"}}",
                 name, names);
        return;
    }
    cJSON * p = (params && *params) ? cJSON_Parse(params) : cJSON_CreateObject();
    if (!cJSON_IsObject(p))
    {
        cJSON_Delete(p);
        snprintf(out, cap, "%s", "{\"ok\":false,\"error\":{\"code\":\"invalid\",\"message\":\"params must be a JSON object\"}}");
        return;
    }
    CallWait * w = new (std::nothrow) CallWait;
    if (w != nullptr)
    {
        w->done   = xSemaphoreCreateBinary();
        w->result = nullptr;
    }
    if (w == nullptr || w->done == nullptr)
    {
        cJSON_Delete(p);
        snprintf(out, cap, "%s", "{\"ok\":false,\"error\":{\"code\":\"no_memory\",\"message\":\"\"}}");
        return;
    }
    const ctf_reply_sink_t sink = { call_sink, w };
    cJSON * r                   = ctf_cmd_dispatch(name, p, &sink);
    cJSON_Delete(p);
    if (r != CTF_ASYNC)
    {
        write_result(r, out, cap);
        cJSON_Delete(r);
        w->refs.fetch_sub(1); // the sink will never be called
        call_wait_release(w);
        return;
    }
    uint32_t wait_ms = (def->timeout_ms ? def->timeout_ms : 60000) + 5000;
    if (xSemaphoreTake(w->done, pdMS_TO_TICKS(wait_ms)) == pdTRUE)
    {
        write_result(w->result, out, cap);
    }
    else
    {
        snprintf(out, cap, "%s", "{\"ok\":false,\"error\":{\"code\":\"timeout\",\"message\":\"no result in time\"}}");
    }
    call_wait_release(w);
}

// Frames the CHIP thread sends (ICD Check-In events, the signer's requests)
// go out from a task of their own: socket writes block.
struct OutFrame
{
    uint32_t conn; // 0: an ICD event for `node`, to every connection
    uint64_t node;
    uint8_t * body; // malloc'd control frame body
    size_t len;
};
QueueHandle_t s_events;

void icd_active(uint64_t node)
{
    OutFrame f = { 0, node, nullptr, 0 };
    if (s_events != nullptr)
    {
        xQueueSend(s_events, &f, 0);
    }
}

void event_task(void *)
{
    OutFrame f;
    while (xQueueReceive(s_events, &f, portMAX_DELAY) == pdTRUE)
    {
        if (f.conn == 0)
        {
            size_t n = ctf::SendEvent(ctf::kEventIcdActive, f.node);
            ESP_LOGI(TAG, "node %llu checked in: told %u connection(s)", (unsigned long long) f.node, (unsigned) n);
            continue;
        }
        ctf::SendToConnection(f.conn, ctf::kFrameControl, f.body, f.len);
        free(f.body);
    }
}

struct InitArgs
{
    bool ok;
};

void init_in_chip_task(void * p)
{
    auto * a       = static_cast<InitArgs *>(p);
    auto * commish = esp_matter::controller::matter_controller_client::get_instance().get_commissioner();
    auto * state   = chip::Controller::DeviceControllerFactory::GetInstance().GetSystemState();
    if (commish == nullptr || state == nullptr || state->TransportMgr() == nullptr)
    {
        a->ok = false;
        return;
    }
    ctf_ca_install_verifier(commish);
    ctf::Relay::Config rc;
    rc.controller  = commish;
    rc.nodeAllowed = node_allowed;
    a->ok         = ctf::Relay::Instance().Init(rc) == CHIP_NO_ERROR;
    // DeviceTransportMgr: [0] UDP over IPv6, [1] UDP over IPv4 (same port).
    s_chip_port = state->TransportMgr()->GetTransport().GetImplAtIndex<1>().GetBoundPort();
}

// Where cloud controllers connect from (chip_tool_forwarder_config_t): one
// lwIP netif, by its two-letter name, or every interface; never both.
char s_listen_netif[3];

// The listen netif's full name (name and number), once the application has
// added it (a tunnel, for example, once it starts).
bool listen_ifname(char * name, size_t cap)
{
    bool found = false;
    LOCK_TCPIP_CORE();
    struct netif * n;
    NETIF_FOREACH(n)
    {
        if (n->name[0] == s_listen_netif[0] && n->name[1] == s_listen_netif[1])
        {
            snprintf(name, cap, "%c%c%u", n->name[0], n->name[1], static_cast<unsigned>(n->num));
            found = true;
            break;
        }
    }
    UNLOCK_TCPIP_CORE();
    return found;
}

// The listener on one netif (a tunnel, for example): bound to that interface,
// so its replies leave through it (lwIP would otherwise route by source
// address, over Wi-Fi), and to the station address, which is what a tunnel's
// far end dials. Opened once the netif exists, moved when the station address
// changes.
void netif_listener_task(void *)
{
    char ifname[8];
    int handle    = -1;
    uint32_t bound = 0;
    for (;;)
    {
        esp_netif_ip_info_t ip = {};
        esp_netif_t * sta      = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (sta != nullptr && esp_netif_get_ip_info(sta, &ip) == ESP_OK && ip.ip.addr != 0 && ip.ip.addr != bound &&
            listen_ifname(ifname, sizeof(ifname)))
        {
            ctf::RemoveListener(handle);
            handle = ctf::AddListener(ifname, ip.ip.addr); // the server copies the name
            bound  = handle >= 0 ? ip.ip.addr : 0;
            if (handle >= 0)
            {
                ESP_LOGI(TAG, "TCP %u reachable through %s (" IPSTR ")", kPort, ifname, IP2STR(&ip.ip));
            }
        }
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}

void start_task(void *)
{
    // Wait for the controller (set up on the CHIP thread after start).
    for (int i = 0; i < 120; i++)
    {
        InitArgs a = { false };
        ctf::RunInChipTask(init_in_chip_task, &a);
        if (a.ok)
        {
            ctf::ServerConfig sc;
            sc.port           = kPort;
            sc.chipUdpPort    = s_chip_port;
            sc.maxConnections = CONFIG_CHIP_TOOL_FORWARDER_MAX_CONNECTIONS;
            sc.spawn          = spawn;
            sc.call           = call_cmd;
            sc.alloc          = psram_alloc;
            sc.release        = psram_release;
            sc.secretLen      = ctf_secret_ensure(sc.secret, sizeof(sc.secret));
            const bool one_netif = s_listen_netif[0] != '\0';
            sc.anyAddress        = !one_netif;
            if (!ctf::StartServer(sc))
            {
                ESP_LOGE(TAG, "TCP %u: listen failed", kPort);
            }
            else if (one_netif)
            {
                spawn(netif_listener_task, nullptr, "ctf_netif", kTaskStack);
            }
            memset(sc.secret, 0, sizeof(sc.secret));
            s_events = xQueueCreate(16, sizeof(OutFrame));
            if (s_events != nullptr)
            {
                spawn(event_task, nullptr, "ctf_event", kEventStack);
                ctf_ctl_set_icd_listener(icd_active);
            }
            ESP_LOGI(TAG, "relay on TCP %u, TLS, from %s (CHIP UDP %u), secret %s", kPort,
                     one_netif ? s_listen_netif : "every interface", s_chip_port,
                     ctf_secret_is_set() ? "set" : "NOT SET");
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    ESP_LOGE(TAG, "no Matter controller after 120 s; relay not started");
}

} // namespace

extern "C" void ctf_start(const char * listen_netif)
{
    if (s_started)
    {
        return;
    }
    s_started = true;
    if (listen_netif != nullptr)
    {
        snprintf(s_listen_netif, sizeof(s_listen_netif), "%s", listen_netif);
    }
    spawn(start_task, nullptr, "ctf_start", kTaskStack);
}

namespace {

struct StatsArgs
{
    ctf::RelayStats stats;
    size_t sessions, subs, pairs;
};

void stats_in_chip_task(void * p)
{
    auto * a     = static_cast<StatsArgs *>(p);
    auto & r     = ctf::Relay::Instance();
    a->stats     = r.Stats();
    a->sessions  = r.SessionCount();
    a->subs      = r.SubscriptionCount();
    a->pairs     = r.PairCount();
}

// Over the stream, which runs once the server started: it always has a secret.
cJSON * status_cmd(const cJSON *, ctf_reply_t *)
{
    cJSON * p = cJSON_CreateObject();
    cJSON_AddBoolToObject(p, "running", ctf::ServerRunning());
    cJSON_AddNumberToObject(p, "tcp_port", kPort);
    cJSON_AddBoolToObject(p, "secret_set", ctf_secret_is_set());
    cJSON_AddStringToObject(p, "fabric_ca", ctf_ca_enrolled() ? "cloud" : "not_enrolled");
    cJSON * heap = cJSON_AddObjectToObject(p, "heap");
    cJSON_AddNumberToObject(heap, "internal_free", heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(heap, "internal_min", heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(heap, "internal_largest", heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(heap, "psram_free", heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    ctf::ServerStats ss = ctf::GetServerStats();
    cJSON * c = cJSON_AddObjectToObject(p, "connections");
    cJSON_AddNumberToObject(c, "active", ss.active);
    cJSON_AddNumberToObject(c, "accepted", ss.accepted);
    cJSON_AddNumberToObject(c, "refused", ss.refused);
    cJSON_AddNumberToObject(c, "auth_failures", ss.authFailures);
    cJSON_AddNumberToObject(c, "frames_in", ss.framesIn);
    cJSON_AddNumberToObject(c, "frames_out", ss.framesOut);
    if (ctf::Relay::Instance().IsReady())
    {
        StatsArgs a = {};
        ctf::RunInChipTask(stats_in_chip_task, &a);
        cJSON * r = cJSON_AddObjectToObject(p, "relay");
        cJSON_AddNumberToObject(r, "sessions", a.sessions);
        cJSON_AddNumberToObject(r, "subscriptions", a.subs);
        cJSON_AddNumberToObject(r, "exchanges_open", a.pairs);
        cJSON_AddNumberToObject(r, "sessions_opened", a.stats.sessionsOpened);
        cJSON_AddNumberToObject(r, "exchanges_from_cloud", a.stats.exchangesFromCloud);
        cJSON_AddNumberToObject(r, "reports_from_nodes", a.stats.reportsFromDevice);
        cJSON_AddNumberToObject(r, "messages_to_nodes", a.stats.messagesToDevice);
        cJSON_AddNumberToObject(r, "messages_to_cloud", a.stats.messagesToCloud);
        cJSON_AddNumberToObject(r, "node_unreachable", a.stats.deviceConnectFailures);
        cJSON_AddNumberToObject(r, "timeouts", a.stats.timeouts);
        cJSON_AddNumberToObject(r, "send_failures", a.stats.sendFailures);
    }
    return ctf_result_ok(p);
}

/* forwarder relay (TCP 7401): whether it runs, whether the secret is set,
 * the fabric CA, memory, cloud connections, relayed sessions, subscriptions
 * and counters. */
const ctf_cmd_def_t s_status = {
    .name = "matter.gateway_status",
    .fn   = status_cmd,
};

} // namespace

// What chip-tool-remote needs to connect to this forwarder. Offered only on the
// application's own channel, which it authenticates (for example, a channel
// the pairing authenticates), so the secret goes only to that channel's user.
// rotate replaces the secret first and closes every connection.
extern "C" cJSON * ctf_connect(bool rotate)
{
    if (!ctf::ServerRunning())
    {
        return ctf_result_err("not_running", "%s", "the forwarder isn't running yet (setup, Wi-Fi or the controller)");
    }
    size_t closed = 0;
    if (rotate)
    {
        closed = ctf_secret_rotate();
        if (closed == SIZE_MAX)
        {
            return ctf_result_err("nvs", "%s", "the new secret couldn't be stored");
        }
    }
    esp_netif_ip_info_t ip = {};
    esp_netif_t * sta      = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta == nullptr || esp_netif_get_ip_info(sta, &ip) != ESP_OK || ip.ip.addr == 0)
    {
        return ctf_result_err("no_address", "%s", "no Wi-Fi address yet");
    }
    char endpoint[32];
    snprintf(endpoint, sizeof(endpoint), IPSTR ":%u", IP2STR(&ip.ip), kPort);
    char hex[2 * ctf::kMaxSecretLen + 1] = { 0 };
    if (!ctf_secret_hex(hex, sizeof(hex)))
    {
        return ctf_result_err("no_secret", "%s", "the forwarder has no secret yet");
    }
    cJSON * p = cJSON_CreateObject();
    cJSON_AddStringToObject(p, "endpoint", endpoint);
    cJSON_AddStringToObject(p, "secret", hex);
    memset(hex, 0, sizeof(hex));
    if (rotate)
    {
        cJSON_AddNumberToObject(p, "connections_closed", static_cast<double>(closed));
    }
    cJSON_AddStringToObject(p, "client", CTF_CLIENT_RELEASE);
    return ctf_result_ok(p);
}

extern "C" bool ctf_send_later(uint32_t conn, const uint8_t * body, size_t len)
{
    OutFrame f = { conn, 0, static_cast<uint8_t *>(malloc(len)), len };
    if (s_events == nullptr || f.body == nullptr)
    {
        free(f.body);
        return false;
    }
    memcpy(f.body, body, len);
    if (xQueueSend(s_events, &f, 0) != pdTRUE)
    {
        free(f.body);
        return false;
    }
    return true;
}

extern "C" void ctf_register(void)
{
    ctf_ca_init(); // before the Matter controller starts; registers matter.enroll
    ctf_cmd_register(&s_status);
}
