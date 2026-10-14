// SPDX-License-Identifier: Apache-2.0

// The commands a cloud controller calls over the gateway stream (gateway.cpp
// call_cmd: every command registered here). A command answers at once, or
// returns MGW_ASYNC and answers later through its reply. Parameters are
// checked against the definition before the handler runs.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MGW_PARAM_STRING,
    MGW_PARAM_INTEGER, /* a whole number, exact in a double (|v| <= 2^53) */
    MGW_PARAM_BOOLEAN,
} mgw_param_type_t;

typedef struct {
    const char *name;
    mgw_param_type_t type;
} mgw_param_t;

typedef struct mgw_reply mgw_reply_t;

// Returns a result (mgw_result_ok/err), or MGW_ASYNC and calls mgw_reply_send()
// once later.
typedef cJSON *(*mgw_cmd_fn_t)(const cJSON *params, mgw_reply_t *reply);

typedef struct {
    const char *name;
    const mgw_param_t *required;
    size_t n_required;
    const mgw_param_t *optional;
    size_t n_optional;
    uint32_t timeout_ms; // how long a caller waits for an async result; 0: 60 s
    mgw_cmd_fn_t fn;
} mgw_cmd_def_t;

extern cJSON *const MGW_ASYNC;

#define MGW_CMD_MAX 16

// At start-up, before any command arrives (the table is read without a lock).
int mgw_cmd_register(const mgw_cmd_def_t *def);
const mgw_cmd_def_t *mgw_cmd_find(const char *name);
// The registered names, ", " between them, in out (truncated to cap).
void mgw_cmd_names(char *out, size_t cap);

// Where an async result goes.
typedef struct {
    void (*send)(void *ctx, cJSON *result);
    void *ctx;
} mgw_reply_sink_t;

// NULL if there is no such command; MGW_ASYNC if the result comes through sink;
// else the result (the caller owns it).
cJSON *mgw_cmd_dispatch(const char *name, const cJSON *params, const mgw_reply_sink_t *sink);
void mgw_reply_send(mgw_reply_t *reply, cJSON *result);

// {"ok":true,"payload":...} (takes payload) and {"ok":false,"error":{code,message}}.
cJSON *mgw_result_ok(cJSON *payload);
cJSON *mgw_result_err(const char *code, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
bool mgw_result_is_ok(const cJSON *result);

const char *mgw_param_str(const cJSON *params, const char *name, const char *dflt);
long long mgw_param_int(const cJSON *params, const char *name, long long dflt);
bool mgw_param_bool(const cJSON *params, const char *name, bool dflt);

#ifdef __cplusplus
}
#endif
