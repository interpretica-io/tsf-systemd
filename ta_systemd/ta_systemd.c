/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Agent-side systemd introspection over libsystemd's sd-bus
 *
 * Written against the sd-bus API (sd_bus_open_system, sd_bus_call_method
 * and the sd_bus_get_property* helpers). Read-only: it calls the
 * Manager's ListUnits and reads a service's exec-context properties off
 * org.freedesktop.systemd1; it starts, stops and changes nothing. The
 * bus is opened and closed inside each call, so nothing has to survive
 * between calls.
 */

#define TE_LGR_USER     "TA SYSTEMD"

#include "te_config.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <systemd/sd-bus.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "logger_api.h"

#include "ta_systemd.h"

#define SYSTEMD_DEST    "org.freedesktop.systemd1"
#define SYSTEMD_PATH    "/org/freedesktop/systemd1"
#define SYSTEMD_MANAGER "org.freedesktop.systemd1.Manager"
#define SYSTEMD_SERVICE "org.freedesktop.systemd1.Service"

/** A negative sd-bus/errno return turned into a TE status, logged. */
static te_errno
sd_rc(int r, const char *what)
{
    if (r >= 0)
        return 0;

    ERROR("%s: %s", what, strerror(-r));
    switch (-r)
    {
        case ENOENT:
            return TE_RC(TE_TA_UNIX, TE_ENOENT);
        case EACCES:
        case EPERM:
            return TE_RC(TE_TA_UNIX, TE_EACCES);
        case ENOMEM:
            return TE_RC(TE_TA_UNIX, TE_ENOMEM);
        default:
            return TE_RC(TE_TA_UNIX, TE_EFAIL);
    }
}

/* See description in ta_systemd.h */
te_errno
ta_systemd_list(int *count, te_string *result)
{
    sd_bus *bus = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    te_errno rc;
    int r;

    *count = 0;

    r = sd_bus_open_system(&bus);
    if (r < 0)
        return sd_rc(r, "sd_bus_open_system");

    r = sd_bus_call_method(bus, SYSTEMD_DEST, SYSTEMD_PATH, SYSTEMD_MANAGER,
                           "ListUnits", &error, &reply, "");
    if (r < 0)
    {
        ERROR("ListUnits: %s", error.message != NULL ? error.message :
              strerror(-r));
        rc = sd_rc(r, "ListUnits");
        goto out;
    }

    r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY,
                                       "(ssssssouso)");
    if (r < 0)
    {
        rc = sd_rc(r, "enter ListUnits array");
        goto out;
    }

    for (;;)
    {
        const char *name;
        const char *desc;
        const char *load;
        const char *active;
        const char *sub;
        const char *followed;
        const char *unit_path;
        const char *job_type;
        const char *job_path;
        uint32_t job_id;

        r = sd_bus_message_read(reply, "(ssssssouso)", &name, &desc, &load,
                                &active, &sub, &followed, &unit_path,
                                &job_id, &job_type, &job_path);
        if (r < 0)
        {
            rc = sd_rc(r, "read unit record");
            goto out;
        }
        if (r == 0)
            break;

        te_string_append(result, "%s\t%s\t%s\t%s\t%s\n", name, load, active,
                         sub, desc);
        (*count)++;
    }

    sd_bus_message_exit_container(reply);
    rc = 0;

out:
    sd_bus_error_free(&error);
    sd_bus_message_unref(reply);
    sd_bus_unref(bus);

    return rc;
}

/** Append @c "key\tvalue\n" for a string property; skip on error. */
static void
prop_string(sd_bus *bus, const char *path, const char *key, te_string *out)
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    char *value = NULL;

    if (sd_bus_get_property_string(bus, SYSTEMD_DEST, path, SYSTEMD_SERVICE,
                                   key, &error, &value) >= 0)
    {
        te_string_append(out, "%s\t%s\n", key, value != NULL ? value : "");
    }
    free(value);
    sd_bus_error_free(&error);
}

/** Append @c "key\t0|1\n" for a boolean property; skip on error. */
static void
prop_bool(sd_bus *bus, const char *path, const char *key, te_string *out)
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int value = 0;

    if (sd_bus_get_property_trivial(bus, SYSTEMD_DEST, path, SYSTEMD_SERVICE,
                                    key, &error, 'b', &value) >= 0)
    {
        te_string_append(out, "%s\t%d\n", key, value != 0 ? 1 : 0);
    }
    sd_bus_error_free(&error);
}

/** Append @c "key\t<decimal>\n" for a uint64 property; skip on error. */
static void
prop_u64(sd_bus *bus, const char *path, const char *key, te_string *out)
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    uint64_t value = 0;

    if (sd_bus_get_property_trivial(bus, SYSTEMD_DEST, path, SYSTEMD_SERVICE,
                                    key, &error, 't', &value) >= 0)
    {
        te_string_append(out, "%s\t%llu\n", key,
                         (unsigned long long)value);
    }
    sd_bus_error_free(&error);
}

/**
 * Count the entries of a @c (bas) filter property (SystemCallFilter,
 * RestrictAddressFamilies) and append @c "outkey\t<count>\n".
 */
static void
prop_filter_count(sd_bus *bus, const char *path, const char *key,
                  const char *outkey, te_string *out)
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    int count = 0;
    int whitelist = 0;

    if (sd_bus_get_property(bus, SYSTEMD_DEST, path, SYSTEMD_SERVICE, key,
                            &error, &reply, "(bas)") >= 0)
    {
        if (sd_bus_message_enter_container(reply, SD_BUS_TYPE_STRUCT,
                                           "bas") >= 0)
        {
            const char *entry;

            sd_bus_message_read(reply, "b", &whitelist);
            if (sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY,
                                               "s") >= 0)
            {
                while (sd_bus_message_read(reply, "s", &entry) > 0)
                    count++;
                sd_bus_message_exit_container(reply);
            }
            sd_bus_message_exit_container(reply);
        }
        te_string_append(out, "%s\t%d\n", outkey, count);
    }

    sd_bus_message_unref(reply);
    sd_bus_error_free(&error);
}

/* See description in ta_systemd.h */
te_errno
ta_systemd_props(const char *unit, te_string *result)
{
    sd_bus *bus = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    char *path = NULL;
    const char *tmp = NULL;
    te_errno rc;
    int r;

    r = sd_bus_open_system(&bus);
    if (r < 0)
        return sd_rc(r, "sd_bus_open_system");

    /* Resolve the unit's object path. GetUnit finds a loaded unit;
     * LoadUnit loads it into memory (reads its config, does not start
     * it) when it is not loaded yet. */
    r = sd_bus_call_method(bus, SYSTEMD_DEST, SYSTEMD_PATH, SYSTEMD_MANAGER,
                           "GetUnit", &error, &reply, "s", unit);
    if (r < 0)
    {
        sd_bus_error_free(&error);
        sd_bus_message_unref(reply);
        reply = NULL;
        r = sd_bus_call_method(bus, SYSTEMD_DEST, SYSTEMD_PATH,
                               SYSTEMD_MANAGER, "LoadUnit", &error, &reply,
                               "s", unit);
    }
    if (r < 0)
    {
        ERROR("no such unit '%s': %s", unit,
              error.message != NULL ? error.message : strerror(-r));
        rc = TE_RC(TE_TA_UNIX, TE_ENOENT);
        goto out;
    }

    r = sd_bus_message_read(reply, "o", &tmp);
    if (r < 0 || tmp == NULL)
    {
        rc = sd_rc(r < 0 ? r : -EINVAL, "read unit path");
        goto out;
    }
    path = TE_STRDUP(tmp);

    prop_bool(bus, path, "NoNewPrivileges", result);
    prop_string(bus, path, "ProtectSystem", result);
    prop_string(bus, path, "ProtectHome", result);
    prop_bool(bus, path, "PrivateTmp", result);
    prop_bool(bus, path, "PrivateDevices", result);
    prop_bool(bus, path, "ProtectKernelModules", result);
    prop_bool(bus, path, "ProtectKernelTunables", result);
    prop_bool(bus, path, "DynamicUser", result);
    prop_string(bus, path, "User", result);
    prop_u64(bus, path, "CapabilityBoundingSet", result);
    prop_u64(bus, path, "AmbientCapabilities", result);
    prop_u64(bus, path, "RestrictNamespaces", result);
    prop_filter_count(bus, path, "SystemCallFilter",
                      "SystemCallFilterCount", result);
    prop_filter_count(bus, path, "RestrictAddressFamilies",
                      "RestrictAddressFamiliesCount", result);
    rc = 0;

out:
    free(path);
    sd_bus_error_free(&error);
    sd_bus_message_unref(reply);
    sd_bus_unref(bus);

    return rc;
}
