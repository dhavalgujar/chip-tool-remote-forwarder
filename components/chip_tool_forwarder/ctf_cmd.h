// SPDX-License-Identifier: Apache-2.0

// The commands a cloud controller calls over the forwarder stream (forwarder.cpp
// call_cmd: every command registered here). A command answers at once, or
// returns CTF_ASYNC and answers later through its reply. Parameters are
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
    CTF_PARAM_STRING,
    CTF_PARAM_INTEGER, /* a whole number, exact in a double (|v| <= 2^53) */
    CTF_PARAM_BOOLEAN,
} ctf_param_type_t;

typedef struct {
    const char *name;
    ctf_param_type_t type;
} ctf_param_t;

typedef struct ctf_reply ctf_reply_t;

// Returns a result (ctf_result_ok/err), or CTF_ASYNC and calls ctf_reply_send()
// once later.
typedef cJSON *(*ctf_cmd_fn_t)(const cJSON *params, ctf_reply_t *reply);

typedef struct {
    const char *name;
    const ctf_param_t *required;
    size_t n_required;
    const ctf_param_t *optional;
    size_t n_optional;
    uint32_t timeout_ms; // how long a caller waits for an async result; 0: 60 s
    ctf_cmd_fn_t fn;
} ctf_cmd_def_t;

extern cJSON *const CTF_ASYNC;

#define CTF_CMD_MAX 16

// At start-up, before any command arrives (the table is read without a lock).
int ctf_cmd_register(const ctf_cmd_def_t *def);
const ctf_cmd_def_t *ctf_cmd_find(const char *name);
// The registered names, ", " between them, in out (truncated to cap).
void ctf_cmd_names(char *out, size_t cap);

// Where an async result goes.
typedef struct {
    void (*send)(void *ctx, cJSON *result);
    void *ctx;
} ctf_reply_sink_t;

// NULL if there is no such command; CTF_ASYNC if the result comes through sink;
// else the result (the caller owns it).
cJSON *ctf_cmd_dispatch(const char *name, const cJSON *params, const ctf_reply_sink_t *sink);
void ctf_reply_send(ctf_reply_t *reply, cJSON *result);

// {"ok":true,"payload":...} (takes payload) and {"ok":false,"error":{code,message}}.
cJSON *ctf_result_ok(cJSON *payload);
cJSON *ctf_result_err(const char *code, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
bool ctf_result_is_ok(const cJSON *result);

const char *ctf_param_str(const cJSON *params, const char *name, const char *dflt);
long long ctf_param_int(const cJSON *params, const char *name, long long dflt);
bool ctf_param_bool(const cJSON *params, const char *name, bool dflt);

#ifdef __cplusplus
}
#endif
