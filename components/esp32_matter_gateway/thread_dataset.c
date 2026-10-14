// SPDX-License-Identifier: Apache-2.0

/* Operational dataset checks (Thread 1.3, 8.10.1); host-testable. */
#include "thread_cmds.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

enum {
    TLV_CHANNEL = 0,
    TLV_PANID = 1,
    TLV_EXTPANID = 2,
    TLV_NETWORK_NAME = 3,
    TLV_NETWORK_KEY = 5,
    TLV_MESH_LOCAL = 7,
    TLV_ACTIVE_TS = 14,
};

int mgw_thread_hex_decode(const char *hex, uint8_t *out, size_t out_max)
{
    if (!hex) return -1;
    if (strncmp(hex, "hex:", 4) == 0) hex += 4;
    size_t n = 0;
    int nib = -1;
    for (const char *p = hex; *p; p++) {
        if (isspace((unsigned char)*p)) continue;
        int v;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else return -1;
        if (nib < 0) {
            nib = v;
        } else {
            if (n >= out_max) return -1;
            out[n++] = (uint8_t)(nib << 4 | v);
            nib = -1;
        }
    }
    return nib < 0 ? (int)n : -1;
}

const char *mgw_thread_dataset_check(const uint8_t *b, size_t len, mgw_thread_info_t *info)
{
    mgw_thread_info_t dummy;
    if (!info) info = &dummy;
    memset(info, 0, sizeof(*info));
    info->channel = info->pan_id = -1;
    if (!b || len == 0) return "dataset is empty";
    if (len > MGW_THREAD_DATASET_MAX) return "dataset is too long";
    uint32_t seen = 0;
    for (size_t i = 0; i < len;) {
        if (i + 2 > len) return "dataset: truncated TLV header";
        uint8_t t = b[i], l = b[i + 1];
        const uint8_t *v = b + i + 2;
        if ((size_t)l > len - i - 2) return "dataset: a TLV is longer than the data";
        /* A required TLV counts only with its exact length (the network name: 1-16). */
        static const struct {
            uint8_t t, len;
        } exact[] = {{TLV_ACTIVE_TS, 8}, {TLV_CHANNEL, 3}, {TLV_PANID, 2}, {TLV_EXTPANID, 8},
                     {TLV_NETWORK_KEY, 16}, {TLV_MESH_LOCAL, 8}};
        bool sized = true;
        for (size_t k = 0; k < sizeof(exact) / sizeof(exact[0]); k++) {
            if (exact[k].t == t && exact[k].len != l) sized = false;
        }
        if (t == TLV_NETWORK_NAME && (l < 1 || l > 16)) sized = false;
        if (!sized) return "dataset: a TLV has the wrong length";
        if (t < 32) {
            if (seen & (1u << t)) return "dataset: a TLV appears twice";
            seen |= 1u << t;
        }
        switch (t) {
        case TLV_CHANNEL:
            if (l == 3) info->channel = v[1] << 8 | v[2];
            break;
        case TLV_PANID:
            if (l == 2) info->pan_id = v[0] << 8 | v[1];
            break;
        case TLV_EXTPANID:
            for (int k = 0; k < l && k < 8; k++) snprintf(info->ext_pan_id + 2 * k, 3, "%02x", v[k]);
            break;
        case TLV_NETWORK_NAME: {
            size_t n = l < 16 ? l : 16;
            memcpy(info->network_name, v, n);
            info->network_name[n] = '\0';
            break;
        }
        case TLV_MESH_LOCAL:
            if (l == 8) {
                snprintf(info->mesh_local, sizeof(info->mesh_local), "%x:%x:%x:%x::/64", v[0] << 8 | v[1],
                         v[2] << 8 | v[3], v[4] << 8 | v[5], v[6] << 8 | v[7]);
            }
            break;
        }
        i += 2 + (size_t)l;
    }
    static const struct {
        uint8_t t;
        const char *what;
    } need[] = {{TLV_ACTIVE_TS, "dataset has no active timestamp TLV: is it the *active* dataset?"},
                {TLV_CHANNEL, "dataset has no channel TLV"},
                {TLV_PANID, "dataset has no PAN ID TLV"},
                {TLV_EXTPANID, "dataset has no extended PAN ID TLV"},
                {TLV_NETWORK_KEY, "dataset has no network key TLV"},
                {TLV_MESH_LOCAL, "dataset has no mesh-local prefix TLV"}};
    for (size_t k = 0; k < sizeof(need) / sizeof(need[0]); k++) {
        if (!(seen & (1u << need[k].t))) return need[k].what;
    }
    return NULL;
}
