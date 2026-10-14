// SPDX-License-Identifier: Apache-2.0

// Host harness for the Matter gateway's pure-C parts (tests/test_host.py):
// the command table's parameter checks and async replies, and the Thread
// dataset checks.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mgw_cmd.h"
#include "thread_cmds.h"

static int failures;
#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); \
            failures++;                                                           \
        }                                                                         \
    } while (0)

static mgw_reply_t *s_pending;
static cJSON *s_sent;
static int s_sink_ctx;

static cJSON *now_cmd(const cJSON *params, mgw_reply_t *reply)
{
    (void)reply;
    cJSON *p = cJSON_CreateObject();
    cJSON_AddNumberToObject(p, "node_id", (double)mgw_param_int(params, "node_id", -1));
    cJSON_AddBoolToObject(p, "forget", mgw_param_bool(params, "forget", false));
    cJSON_AddStringToObject(p, "label", mgw_param_str(params, "label", "none"));
    return mgw_result_ok(p);
}

static cJSON *later_cmd(const cJSON *params, mgw_reply_t *reply)
{
    (void)params;
    s_pending = reply;
    return MGW_ASYNC;
}

static void sink(void *ctx, cJSON *result)
{
    CHECK(ctx == &s_sink_ctx);
    CHECK(s_sent == NULL); /* once */
    s_sent = result;
}

static const mgw_param_t req[] = {{"node_id", MGW_PARAM_INTEGER}};
static const mgw_param_t opt[] = {{"forget", MGW_PARAM_BOOLEAN}, {"label", MGW_PARAM_STRING}};
static const mgw_cmd_def_t s_now = {.name = "matter.now", .required = req, .n_required = 1, .optional = opt,
                                   .n_optional = 2, .fn = now_cmd};
static const mgw_cmd_def_t s_later = {.name = "matter.later", .fn = later_cmd};

static const char *error_code(cJSON *r)
{
    const cJSON *e = cJSON_GetObjectItemCaseSensitive(r, "error");
    const cJSON *c = cJSON_GetObjectItemCaseSensitive(e, "code");
    return cJSON_IsString(c) ? c->valuestring : "";
}

static cJSON *dispatch(const char *name, const char *params_json)
{
    cJSON *params = params_json ? cJSON_Parse(params_json) : NULL;
    mgw_reply_sink_t s = {.send = sink, .ctx = &s_sink_ctx};
    cJSON *r = mgw_cmd_dispatch(name, params, &s);
    cJSON_Delete(params);
    return r;
}

static void commands(void)
{
    CHECK(mgw_cmd_register(&s_now) == 0);
    CHECK(mgw_cmd_register(&s_later) == 0);
    CHECK(mgw_cmd_register(&s_now) != 0); /* a name once */
    CHECK(mgw_cmd_find("matter.now") == &s_now);
    CHECK(dispatch("matter.none", "{}") == NULL);
    char names[64];
    mgw_cmd_names(names, sizeof(names));
    CHECK(strcmp(names, "matter.now, matter.later") == 0);
    mgw_cmd_names(names, 12); /* truncated, still a string */
    CHECK(strcmp(names, "matter.now,") == 0);

    cJSON *r = dispatch("matter.now", "{}");
    CHECK(!mgw_result_is_ok(r) && strcmp(error_code(r), "missing_param") == 0);
    cJSON_Delete(r);
    r = dispatch("matter.now", "{\"node_id\": 1.5}");
    CHECK(strcmp(error_code(r), "invalid_param") == 0); /* an integer */
    cJSON_Delete(r);
    r = dispatch("matter.now", "{\"node_id\": 1e300}");
    CHECK(strcmp(error_code(r), "invalid_param") == 0); /* past 2^53: not exact */
    cJSON_Delete(r);
    r = dispatch("matter.now", "{\"node_id\": 100, \"forget\": \"yes\"}");
    CHECK(strcmp(error_code(r), "invalid_param") == 0); /* a boolean */
    cJSON_Delete(r);
    r = dispatch("matter.now", "[1]");
    CHECK(strcmp(error_code(r), "invalid_params") == 0);
    cJSON_Delete(r);

    r = dispatch("matter.now", "{\"node_id\": 100, \"forget\": true, \"label\": null}");
    CHECK(mgw_result_is_ok(r));
    const cJSON *p = cJSON_GetObjectItemCaseSensitive(r, "payload");
    CHECK(cJSON_GetObjectItemCaseSensitive(p, "node_id")->valuedouble == 100);
    CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(p, "forget")));
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(p, "label")->valuestring, "none") == 0);
    cJSON_Delete(r);

    /* async: the reply reaches the sink once, with its context */
    r = dispatch("matter.later", NULL);
    CHECK(r == MGW_ASYNC && s_pending != NULL);
    mgw_reply_send(s_pending, mgw_result_err("timeout", "no answer in %d s", 5));
    CHECK(s_sent != NULL && strcmp(error_code(s_sent), "timeout") == 0);
    cJSON_Delete(s_sent);
}

/* OpenThread's documented example active dataset */
static const char *k_ds = "0e080000000000010000000300001435060004001fffe00208dead00beef00cafe0708fddead00beef0000"
                          "051000112233445566778899aabbccddeeff030f4f70656e5468726561642d313233340102123404"
                          "10104810e2315100afd6bc9215a6bfac530c0402a0f7f8";

static void datasets(void)
{
    uint8_t b[MGW_THREAD_DATASET_MAX];
    int n = mgw_thread_hex_decode(k_ds, b, sizeof(b));
    CHECK(n > 0);
    mgw_thread_info_t i;
    CHECK(mgw_thread_dataset_check(b, (size_t)n, &i) == NULL);
    CHECK(strcmp(i.network_name, "OpenThread-1234") == 0);
    CHECK(i.channel == 20 && i.pan_id == 0x1234);
    CHECK(strcmp(i.ext_pan_id, "dead00beef00cafe") == 0);
    CHECK(strcmp(i.mesh_local, "fdde:ad00:beef:0::/64") == 0);

    char prefixed[600];
    snprintf(prefixed, sizeof(prefixed), "hex: %.20s \n%s", k_ds, k_ds + 20);
    CHECK(mgw_thread_hex_decode(prefixed, b, sizeof(b)) == n);
    CHECK(mgw_thread_hex_decode("abc", b, sizeof(b)) < 0); /* odd length */
    CHECK(mgw_thread_hex_decode("zz", b, sizeof(b)) < 0);  /* not hex */
    CHECK(mgw_thread_hex_decode(k_ds, b, 10) < 0);         /* too long for the buffer */

    uint8_t pending[] = {0x01, 0x02, 0xab, 0xcd};
    const char *why = mgw_thread_dataset_check(pending, sizeof(pending), &i);
    CHECK(why && strstr(why, "active"));
    uint8_t trunc[] = {0x0e, 0x08, 0x00};
    CHECK(mgw_thread_dataset_check(trunc, sizeof(trunc), &i) != NULL);
    CHECK(mgw_thread_dataset_check(NULL, 0, &i) != NULL);
    n = mgw_thread_hex_decode(k_ds, b, sizeof(b)); /* without the network key */
    for (int k = 0; k < n;) {
        if (b[k] == 0x05) {
            b[k] = 0x7f;
            break;
        }
        k += 2 + b[k + 1];
    }
    why = mgw_thread_dataset_check(b, (size_t)n, &i);
    CHECK(why && strstr(why, "network key"));
    /* a required TLV with the wrong length, or twice */
    n = mgw_thread_hex_decode("0e0800000000000100000002001435060004001fffe00208dead00beef00cafe0708fddead00beef0000051000112233445566778899aabbccddeeff030f4f70656e5468726561642d31323334010212340410104810e2315100afd6bc9215a6bfac530c0402a0f7f8", b, sizeof(b));
    why = n > 0 ? mgw_thread_dataset_check(b, (size_t)n, &i) : NULL;
    CHECK(why && strstr(why, "wrong length"));
    n = mgw_thread_hex_decode("0e080000000000010000000300001435060004001fffe00208dead00beef00cafe0708fddead00beef0000051000112233445566778899aabbccddeeff030f4f70656e5468726561642d31323334010212340410104810e2315100afd6bc9215a6bfac530c0402a0f7f8000300000b", b, sizeof(b));
    why = n > 0 ? mgw_thread_dataset_check(b, (size_t)n, &i) : NULL;
    CHECK(why && strstr(why, "twice"));
}

int main(void)
{
    commands();
    datasets();
    if (failures) {
        fprintf(stderr, "%d failed\n", failures);
        return 1;
    }
    puts("esp32_matter_gateway: ok");
    return 0;
}
