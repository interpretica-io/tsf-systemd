/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Reading systemd units and service hardening from a test
 *
 * The engine-side layer over the systemd_* RPCs: it asks the agent for
 * the unit list and a service's properties and parses the newline/tab
 * record text into a #tapi_systemd_unit vector and a
 * #tapi_systemd_hardening.
 */

#define TE_LGR_USER     "TAPI SYSTEMD"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"
#include "logger_api.h"

#include "tapi_systemd.h"
#include "tapi_systemd_rpc.h"

/** Number of tab-separated fields in a systemd_list() line. */
#define TAPI_SYSTEMD_FIELDS 5

/** A non-empty string as a heap copy, or @c NULL when empty. */
static char *
str_or_null(const char *s, size_t len)
{
    if (len == 0)
        return NULL;
    return TE_STRNDUP(s, len);
}

/** Parse one systemd_list() line into a unit; false on a short line. */
static bool
parse_unit_line(const char *line, size_t len, tapi_systemd_unit *unit)
{
    const char *p = line;
    const char *end = line + len;
    char *f[TAPI_SYSTEMD_FIELDS];
    size_t i;
    bool ok = true;

    for (i = 0; i < TAPI_SYSTEMD_FIELDS; i++)
    {
        const char *tab = (i + 1 < TAPI_SYSTEMD_FIELDS) ?
                          memchr(p, '\t', (size_t)(end - p)) : NULL;
        size_t flen = (i + 1 < TAPI_SYSTEMD_FIELDS && tab != NULL) ?
                      (size_t)(tab - p) : (size_t)(end - p);

        if (i + 1 < TAPI_SYSTEMD_FIELDS && tab == NULL)
        {
            /* fewer tabs than expected - a malformed line */
            size_t j;

            for (j = 0; j < i; j++)
                free(f[j]);
            return false;
        }
        f[i] = TE_STRNDUP(p, flen);
        p = (tab != NULL) ? tab + 1 : end;
    }

    unit->name = f[0];
    unit->load = f[1];
    unit->active = f[2];
    unit->sub = f[3];
    unit->description = f[4];

    return ok;
}

/* See description in tapi_systemd.h */
te_errno
tapi_systemd_list(rcf_rpc_server *rpcs, te_vec *units)
{
    te_string raw = TE_STRING_INIT;
    const char *line;
    te_errno rc;

    *units = (te_vec)TE_VEC_INIT(tapi_systemd_unit);

    rc = rpc_systemd_list(rpcs, NULL, &raw);
    if (rc != 0)
    {
        te_string_free(&raw);
        return rc;
    }

    line = te_string_value(&raw);
    while (line != NULL && *line != '\0')
    {
        const char *nl = strchr(line, '\n');
        size_t len = nl != NULL ? (size_t)(nl - line) : strlen(line);
        tapi_systemd_unit unit;

        if (len != 0 && parse_unit_line(line, len, &unit))
            TE_VEC_APPEND(units, unit);

        line = nl != NULL ? nl + 1 : NULL;
    }

    te_string_free(&raw);

    return 0;
}

/** Apply one "key\tvalue" property line to a hardening record. */
static void
apply_prop(tapi_systemd_hardening *h, const char *key, size_t klen,
           const char *val, size_t vlen)
{
    char *v = TE_STRNDUP(val, vlen);

#define KEY_IS(_s) (klen == strlen(_s) && strncmp(key, _s, klen) == 0)
    if (KEY_IS("NoNewPrivileges"))
        h->no_new_privileges = (atoi(v) != 0);
    else if (KEY_IS("ProtectSystem"))
        h->protect_system = str_or_null(val, vlen);
    else if (KEY_IS("ProtectHome"))
        h->protect_home = str_or_null(val, vlen);
    else if (KEY_IS("PrivateTmp"))
        h->private_tmp = (atoi(v) != 0);
    else if (KEY_IS("PrivateDevices"))
        h->private_devices = (atoi(v) != 0);
    else if (KEY_IS("ProtectKernelModules"))
        h->protect_kernel_modules = (atoi(v) != 0);
    else if (KEY_IS("ProtectKernelTunables"))
        h->protect_kernel_tunables = (atoi(v) != 0);
    else if (KEY_IS("DynamicUser"))
        h->dynamic_user = (atoi(v) != 0);
    else if (KEY_IS("User"))
        h->user = str_or_null(val, vlen);
    else if (KEY_IS("CapabilityBoundingSet"))
        h->capability_bounding_set = strtoull(v, NULL, 10);
    else if (KEY_IS("AmbientCapabilities"))
        h->ambient_capabilities = strtoull(v, NULL, 10);
    else if (KEY_IS("RestrictNamespaces"))
        h->restrict_namespaces = strtoull(v, NULL, 10);
    else if (KEY_IS("SystemCallFilterCount"))
        h->syscall_filter_count = atoi(v);
    else if (KEY_IS("RestrictAddressFamiliesCount"))
        h->restrict_address_families_count = atoi(v);
#undef KEY_IS

    free(v);
}

/* See description in tapi_systemd.h */
te_errno
tapi_systemd_hardening(rcf_rpc_server *rpcs, const char *unit,
                       tapi_systemd_hardening *out)
{
    te_string raw = TE_STRING_INIT;
    const char *line;
    te_errno rc;

    memset(out, 0, sizeof(*out));
    out->unit = TE_STRDUP(unit);

    rc = rpc_systemd_props(rpcs, unit, &raw);
    if (rc != 0)
    {
        te_string_free(&raw);
        return rc;
    }

    out->present = true;
    line = te_string_value(&raw);
    while (line != NULL && *line != '\0')
    {
        const char *nl = strchr(line, '\n');
        size_t len = nl != NULL ? (size_t)(nl - line) : strlen(line);
        const char *tab = memchr(line, '\t', len);

        if (tab != NULL)
        {
            apply_prop(out, line, (size_t)(tab - line),
                       tab + 1, len - (size_t)(tab - line) - 1);
        }
        line = nl != NULL ? nl + 1 : NULL;
    }

    te_string_free(&raw);

    return 0;
}

/* See description in tapi_systemd.h */
bool
tapi_systemd_cap_has(uint64_t mask, unsigned int cap)
{
    if (cap >= 64)
        return false;
    return (mask & ((uint64_t)1 << cap)) != 0;
}

/* See description in tapi_systemd.h */
void
tapi_systemd_unit_log(const tapi_systemd_unit *unit)
{
    RING("unit %s: %s / %s / %s - %s", unit->name, unit->load,
         unit->active, unit->sub,
         unit->description != NULL ? unit->description : "");
}

/* See description in tapi_systemd.h */
void
tapi_systemd_list_free(te_vec *units)
{
    tapi_systemd_unit *unit;

    TE_VEC_FOREACH(units, unit)
    {
        free(unit->name);
        free(unit->load);
        free(unit->active);
        free(unit->sub);
        free(unit->description);
    }
    te_vec_free(units);
}

/* See description in tapi_systemd.h */
void
tapi_systemd_hardening_free(tapi_systemd_hardening *h)
{
    free(h->unit);
    free(h->protect_system);
    free(h->protect_home);
    free(h->user);
    memset(h, 0, sizeof(*h));
}
