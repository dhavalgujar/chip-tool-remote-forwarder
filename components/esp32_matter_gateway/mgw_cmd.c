// SPDX-License-Identifier: Apache-2.0

// The command table and dispatch; see mgw_cmd.h.
#include "mgw_cmd.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static cJSON s_async_sentinel;
cJSON *const MGW_ASYNC = &s_async_sentinel;

static const mgw_cmd_def_t *s_cmds[MGW_CMD_MAX];
static size_t s_n_cmds;

struct mgw_reply {
    mgw_reply_sink_t sink;
    const mgw_cmd_def_t *cmd;
};

int mgw_cmd_register(const mgw_cmd_def_t *def)
{
    if (!def || !def->name || !def->name[0] || !def->fn) return -1;
    if (mgw_cmd_find(def->name)) return -1;
    if (s_n_cmds >= MGW_CMD_MAX) return -1;
    s_cmds[s_n_cmds++] = def;
    return 0;
}

const mgw_cmd_def_t *mgw_cmd_find(const char *name)
{
    if (!name) return NULL;
    for (size_t i = 0; i < s_n_cmds; i++) {
        if (strcmp(s_cmds[i]->name, name) == 0) return s_cmds[i];
    }
    return NULL;
}

void mgw_cmd_names(char *out, size_t cap)
{
    if (cap == 0) return;
    out[0] = 0;
    for (size_t i = 0; i < s_n_cmds; i++) {
        size_t n = strlen(out);
        snprintf(out + n, cap - n, "%s%s", i ? ", " : "", s_cmds[i]->name);
    }
}

cJSON *mgw_result_ok(cJSON *payload)
{
    cJSON *r = cJSON_CreateObject();
    if (!r) {
        cJSON_Delete(payload);
        return NULL;
    }
    cJSON_AddBoolToObject(r, "ok", true);
    cJSON_AddItemToObject(r, "payload", payload ? payload : cJSON_CreateObject());
    return r;
}

cJSON *mgw_result_err(const char *code, const char *fmt, ...)
{
    char msg[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    cJSON *r = cJSON_CreateObject();
    if (!r) return NULL;
    cJSON_AddBoolToObject(r, "ok", false);
    cJSON *e = cJSON_AddObjectToObject(r, "error");
    if (e) {
        cJSON_AddStringToObject(e, "code", code ? code : "error");
        cJSON_AddStringToObject(e, "message", msg);
    }
    return r;
}

bool mgw_result_is_ok(const cJSON *result)
{
    return result && cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(result, "ok"));
}

static const char *type_name(mgw_param_type_t t)
{
    switch (t) {
    case MGW_PARAM_STRING: return "string";
    case MGW_PARAM_INTEGER: return "integer";
    case MGW_PARAM_BOOLEAN: return "boolean";
    }
    return "string";
}

static bool type_matches(const cJSON *v, mgw_param_type_t t)
{
    switch (t) {
    case MGW_PARAM_STRING: return cJSON_IsString(v) && v->valuestring;
    case MGW_PARAM_INTEGER: /* exact in a double: |v| <= 2^53 */
        return cJSON_IsNumber(v) && isfinite(v->valuedouble) && floor(v->valuedouble) == v->valuedouble &&
               fabs(v->valuedouble) <= 9007199254740992.0;
    case MGW_PARAM_BOOLEAN: return cJSON_IsBool(v);
    }
    return false;
}

/* NULL if params fit the command, else an error result. */
static cJSON *validate(const mgw_cmd_def_t *c, const cJSON *params)
{
    if (params && !cJSON_IsObject(params) && !cJSON_IsNull(params)) {
        return mgw_result_err("invalid_params", "params must be an object");
    }
    for (size_t i = 0; i < c->n_required; i++) {
        const cJSON *v = params ? cJSON_GetObjectItemCaseSensitive(params, c->required[i].name) : NULL;
        if (!v || cJSON_IsNull(v)) {
            return mgw_result_err("missing_param", "%s is required", c->required[i].name);
        }
        if (!type_matches(v, c->required[i].type)) {
            return mgw_result_err("invalid_param", "%s must be %s", c->required[i].name,
                                 type_name(c->required[i].type));
        }
    }
    for (size_t i = 0; i < c->n_optional; i++) {
        const cJSON *v = params ? cJSON_GetObjectItemCaseSensitive(params, c->optional[i].name) : NULL;
        if (v && !cJSON_IsNull(v) && !type_matches(v, c->optional[i].type)) {
            return mgw_result_err("invalid_param", "%s must be %s", c->optional[i].name,
                                 type_name(c->optional[i].type));
        }
    }
    return NULL;
}

cJSON *mgw_cmd_dispatch(const char *name, const cJSON *params, const mgw_reply_sink_t *sink)
{
    const mgw_cmd_def_t *c = mgw_cmd_find(name);
    if (!c) return NULL;
    cJSON *err = validate(c, params);
    if (err) return err;
    mgw_reply_t *reply = calloc(1, sizeof(*reply));
    if (!reply) return mgw_result_err("out_of_memory", "no memory for the reply");
    if (sink) reply->sink = *sink;
    reply->cmd = c;
    cJSON *r = c->fn(params, reply);
    if (r == MGW_ASYNC) return MGW_ASYNC; /* the handler owns reply now */
    free(reply);
    return r ? r : mgw_result_err("internal", "%s returned no result", c->name);
}

void mgw_reply_send(mgw_reply_t *reply, cJSON *result)
{
    if (!reply) {
        cJSON_Delete(result);
        return;
    }
    if (!result) result = mgw_result_err("internal", "%s finished without a result", reply->cmd->name);
    if (reply->sink.send) {
        reply->sink.send(reply->sink.ctx, result);
    } else {
        cJSON_Delete(result);
    }
    free(reply);
}

static const cJSON *param(const cJSON *params, const char *name)
{
    const cJSON *v = params ? cJSON_GetObjectItemCaseSensitive(params, name) : NULL;
    return v && !cJSON_IsNull(v) ? v : NULL;
}

const char *mgw_param_str(const cJSON *params, const char *name, const char *dflt)
{
    const cJSON *v = param(params, name);
    return cJSON_IsString(v) ? v->valuestring : dflt;
}

long long mgw_param_int(const cJSON *params, const char *name, long long dflt)
{
    const cJSON *v = param(params, name);
    return cJSON_IsNumber(v) ? (long long)v->valuedouble : dflt;
}

bool mgw_param_bool(const cJSON *params, const char *name, bool dflt)
{
    const cJSON *v = param(params, name);
    return cJSON_IsBool(v) ? cJSON_IsTrue(v) : dflt;
}
