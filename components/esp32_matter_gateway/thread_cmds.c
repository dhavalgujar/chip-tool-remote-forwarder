// SPDX-License-Identifier: Apache-2.0

// thread.* commands and router re-solicitation; see thread_cmds.h.
#include "thread_cmds.h"

#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "mgw_cmd.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "mgw_nvs.h"

#define TAG "matter_gw_thread"
#define NVS_KEY "dataset"

static esp_netif_t *sta(void) { return esp_netif_get_handle_from_ifkey("WIFI_STA_DEF"); }

bool mgw_thread_dataset_get(uint8_t *tlvs, size_t *len)
{
    nvs_handle_t h;
    if (mgw_nvs_open(NVS_READONLY, &h) != ESP_OK) return false;
    size_t n = *len;
    esp_err_t err = nvs_get_blob(h, NVS_KEY, tlvs, &n);
    nvs_close(h);
    if (err != ESP_OK) return false;
    *len = n;
    return true;
}

static cJSON *info_json(const mgw_thread_info_t *i)
{
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "network_name", i->network_name);
    if (i->channel >= 0) cJSON_AddNumberToObject(o, "channel", i->channel);
    if (i->pan_id >= 0) {
        char pan[12];
        snprintf(pan, sizeof(pan), "0x%04x", i->pan_id);
        cJSON_AddStringToObject(o, "pan_id", pan);
    }
    cJSON_AddStringToObject(o, "ext_pan_id", i->ext_pan_id);
    cJSON_AddStringToObject(o, "mesh_local_prefix", i->mesh_local);
    return o;
}

static cJSON *set_dataset(const cJSON *params, mgw_reply_t *reply)
{
    (void)reply;
    uint8_t tlvs[MGW_THREAD_DATASET_MAX];
    int n = mgw_thread_hex_decode(mgw_param_str(params, "dataset", ""), tlvs, sizeof(tlvs));
    if (n <= 0) return mgw_result_err("invalid_param", "dataset must be hex TLVs (at most %d bytes)", MGW_THREAD_DATASET_MAX);
    mgw_thread_info_t info;
    const char *why = mgw_thread_dataset_check(tlvs, (size_t)n, &info);
    if (why) {
        memset(tlvs, 0, sizeof(tlvs)); /* it holds the network key */
        return mgw_result_err("invalid_dataset", "%s", why);
    }
    nvs_handle_t h;
    esp_err_t err = mgw_nvs_open(NVS_READWRITE, &h);
    if (err == ESP_OK) {
        err = nvs_set_blob(h, NVS_KEY, tlvs, (size_t)n);
        if (err == ESP_OK) err = nvs_commit(h);
        nvs_close(h);
    }
    memset(tlvs, 0, sizeof(tlvs));
    if (err != ESP_OK) return mgw_result_err("storage", "could not store the dataset: %s", esp_err_to_name(err));
    ESP_LOGI(TAG, "dataset stored: network \"%s\", channel %d", info.network_name, info.channel);
    return mgw_result_ok(info_json(&info)); /* the key is never echoed */
}

static cJSON *clear_dataset(const cJSON *params, mgw_reply_t *reply)
{
    (void)params, (void)reply;
    nvs_handle_t h;
    esp_err_t err = mgw_nvs_open(NVS_READWRITE, &h);
    if (err == ESP_OK) {
        err = nvs_erase_key(h, NVS_KEY);
        if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK; /* none stored */
        if (err == ESP_OK) err = nvs_commit(h);
        nvs_close(h);
    }
    if (err != ESP_OK) return mgw_result_err("storage", "could not forget the dataset: %s", esp_err_to_name(err));
    return mgw_result_ok(NULL);
}

/* CHIP's route table (ESP32RouteTable.c, CONFIG_ENABLE_ROUTE_HOOK): next hop
 * for a destination behind another router. Weak: absent without Matter. */
const ip6_addr_t *lwip_hook_nd6_get_gw(struct netif *netif, const ip6_addr_t *dest) __attribute__((weak));

typedef struct {
    ip6_addr_t dest;
    char netif_name[8];
    char via[48];
    bool routed;
} route_query_t;

static void route_query(route_query_t *q)
{
    LOCK_TCPIP_CORE();
    struct netif *n = ip6_route(IP6_ADDR_ANY6, &q->dest);
    if (n) {
        snprintf(q->netif_name, sizeof(q->netif_name), "%c%c%u", n->name[0], n->name[1], n->num);
        const ip6_addr_t *gw = lwip_hook_nd6_get_gw ? lwip_hook_nd6_get_gw(n, &q->dest) : NULL;
        if (gw) {
            ip6addr_ntoa_r(gw, q->via, sizeof(q->via));
            q->routed = true;
        }
    }
    UNLOCK_TCPIP_CORE();
}

static cJSON *status(const cJSON *params, mgw_reply_t *reply)
{
    (void)reply;
    cJSON *p = cJSON_CreateObject();
    uint8_t tlvs[MGW_THREAD_DATASET_MAX];
    size_t n = sizeof(tlvs);
    mgw_thread_info_t info;
    if (mgw_thread_dataset_get(tlvs, &n) && !mgw_thread_dataset_check(tlvs, n, &info)) {
        cJSON_AddBoolToObject(p, "dataset", true);
        cJSON_AddItemToObject(p, "network", info_json(&info));
    } else {
        cJSON_AddBoolToObject(p, "dataset", false);
    }
    memset(tlvs, 0, sizeof(tlvs));
    cJSON *addrs = cJSON_AddArrayToObject(p, "ipv6");
    esp_netif_t *s = sta();
    esp_ip6_addr_t ip6[CONFIG_LWIP_IPV6_NUM_ADDRESSES];
    int k = s ? esp_netif_get_all_ip6(s, ip6) : 0;
    for (int i = 0; i < k; i++) {
        char buf[48];
        snprintf(buf, sizeof(buf), IPV6STR, IPV62STR(ip6[i]));
        cJSON_AddItemToArray(addrs, cJSON_CreateString(buf));
    }
    const char *to = mgw_param_str(params, "address", NULL);
    if (to) {
        route_query_t q = {0};
        if (!ip6addr_aton(to, &q.dest)) {
            cJSON_Delete(p);
            return mgw_result_err("invalid_param", "address must be an IPv6 address");
        }
        route_query(&q);
        cJSON *r = cJSON_AddObjectToObject(p, "route");
        cJSON_AddStringToObject(r, "address", to);
        cJSON_AddBoolToObject(r, "route_hook", lwip_hook_nd6_get_gw != NULL);
        cJSON_AddBoolToObject(r, "via_router", q.routed);
        if (q.routed) cJSON_AddStringToObject(r, "next_hop", q.via);
        cJSON_AddStringToObject(r, "netif", q.netif_name);
    }
    return mgw_result_ok(p);
}

/* ---- router re-solicitation ---------------------------------------------- */
/* lwIP solicits an RA when the link comes up and stops at the first one, which
 * can arrive before CHIP's route hook is listening; the TBR's next unsolicited
 * RA (with the OMR prefix's RIO) may be minutes away. So solicit again a few
 * seconds after each IPv6 address event. */
static esp_timer_handle_t s_rs_timer;

static void rs_in_tcpip(void *arg)
{
    struct netif *n = arg;
    if (n) n->rs_count = LWIP_ND6_MAX_MULTICAST_SOLICIT;
}

static void rs_now(void *arg)
{
    (void)arg;
    esp_netif_t *s = sta();
    if (s) tcpip_callback(rs_in_tcpip, esp_netif_get_netif_impl(s));
}

static void rs_later(void)
{
    esp_timer_stop(s_rs_timer);
    esp_timer_start_once(s_rs_timer, 3 * 1000 * 1000);
}

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg, (void)base, (void)id;
    const ip_event_got_ip6_t *ev = data;
    if (ev && ev->esp_netif == sta()) rs_later();
}

void mgw_thread_start(void)
{
    // CHIP makes the station's link-local address when it connects.
    const esp_timer_create_args_t args = {.callback = rs_now, .name = "matter_router_solicit"};
    if (esp_timer_create(&args, &s_rs_timer) != ESP_OK) return;
    esp_event_handler_register(IP_EVENT, IP_EVENT_GOT_IP6, on_event, NULL);
    rs_later();
}

/* dataset: the home Thread Border Router's active dataset, hex TLVs (e.g.
 * `ot-ctl dataset active -x`). It holds the network key: stored here, never
 * returned. */
static const mgw_param_t set_req[] = {{"dataset", MGW_PARAM_STRING}};
/* address: an IPv6 address (e.g. a Thread device's); reports whether a route
 * to it is known. */
static const mgw_param_t status_opt[] = {{"address", MGW_PARAM_STRING}};

static const mgw_cmd_def_t s_cmds[] = {
    /* Store the home Thread network's dataset, used when commissioning Thread
     * devices (matter.commission). This device has no Thread radio: Thread
     * devices join the home's existing Thread Border Router, which routes to
     * them. Returns the network's public fields. */
    {.name = "thread.set_dataset", .required = set_req, .n_required = 1, .fn = set_dataset},
    /* Whether a dataset is stored (and its network name, channel, PAN IDs,
     * mesh-local prefix), this device's IPv6 addresses, and optionally whether
     * a route to an address via a border router is known. */
    {.name = "thread.status", .optional = status_opt, .n_optional = 1, .fn = status},
    /* Forget the stored Thread dataset. */
    {.name = "thread.clear_dataset", .fn = clear_dataset},
};

void mgw_thread_register(void)
{
    for (size_t i = 0; i < sizeof(s_cmds) / sizeof(s_cmds[0]); i++) mgw_cmd_register(&s_cmds[i]);
}
