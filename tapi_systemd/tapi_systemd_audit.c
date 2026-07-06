/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief What a service's systemd sandboxing is worth as a posture
 *
 * Reads each service's hardening with tapi_systemd_hardening() and
 * classifies it into tsf-cybersec findings. Read-only.
 */

#define TE_LGR_USER     "TAPI SYSTEMD AUDIT"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "logger_api.h"

#include "tapi_systemd.h"
#include "tapi_systemd_audit.h"

/* See description in tapi_systemd_audit.h */
const tapi_systemd_audit_policy tapi_systemd_default_audit_policy = {
    .services = NULL,
};

/** Does a unit name end in ".service"? */
static bool
is_service(const char *name)
{
    size_t n = strlen(name);
    size_t s = strlen(".service");

    return n >= s && strcmp(name + n - s, ".service") == 0;
}

/** Is a capability bounding set effectively unrestricted? */
static bool
caps_unrestricted(uint64_t mask)
{
    /* The default (no CapabilityBoundingSet=) leaves every capability
     * in the bounding set, which systemd exposes as an all-ones mask;
     * and holding CAP_SYS_ADMIN is close enough to root to count. */
    return mask == UINT64_MAX ||
           tapi_systemd_cap_has(mask, TAPI_SYSTEMD_CAP_SYS_ADMIN);
}

/** Classify one service's hardening into findings. */
static void
audit_service(const tapi_systemd_hardening *h, tapi_cybersec_report *report)
{
    const char *unit = h->unit;

    if (!h->present)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
            "systemd.not-assessed", unit,
            "the service '%s' could not be read", unit);
        return;
    }

    tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
        "systemd.service-present", unit, "service '%s' assessed", unit);

    if (caps_unrestricted(h->capability_bounding_set))
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
            "systemd.caps-unrestricted", unit,
            "CapabilityBoundingSet is unbounded or holds CAP_SYS_ADMIN "
            "(mask 0x%llx)",
            (unsigned long long)h->capability_bounding_set);
    }

    if (!h->no_new_privileges)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
            "systemd.no-new-privileges-off", unit,
            "NoNewPrivileges is not set");
    }

    {
        bool ps_off = (h->protect_system == NULL ||
                       strcmp(h->protect_system, "no") == 0);
        bool ph_off = (h->protect_home == NULL ||
                       strcmp(h->protect_home, "no") == 0);

        if (ps_off && ph_off)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                "systemd.no-filesystem-protection", unit,
                "neither ProtectSystem nor ProtectHome is in effect");
        }
    }

    if (h->syscall_filter_count == 0)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
            "systemd.syscalls-unfiltered", unit,
            "no SystemCallFilter is set");
    }

    if ((h->user == NULL || strcmp(h->user, "root") == 0) &&
        !h->dynamic_user && !h->no_new_privileges)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
            "systemd.runs-as-root", unit,
            "runs as root with no NoNewPrivileges");
    }
}

/** Audit one named service: read its hardening, classify, free. */
static te_errno
audit_one(rcf_rpc_server *rpcs, const char *unit,
          tapi_cybersec_report *report)
{
    tapi_systemd_hardening h;
    te_errno rc = tapi_systemd_hardening(rpcs, unit, &h);

    if (rc != 0 && TE_RC_GET_ERROR(rc) == TE_ENOENT)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
            "systemd.not-assessed", unit,
            "there is no unit '%s'", unit);
        return 0;
    }
    if (rc != 0)
        return rc;

    audit_service(&h, report);
    tapi_systemd_hardening_free(&h);

    return 0;
}

/* See description in tapi_systemd_audit.h */
te_errno
tapi_systemd_audit(rcf_rpc_server *rpcs,
                   const tapi_systemd_audit_policy *policy,
                   tapi_cybersec_report *report)
{
    te_errno rc = 0;

    if (policy == NULL)
        policy = &tapi_systemd_default_audit_policy;

    if (policy->services != NULL)
    {
        size_t i;

        for (i = 0; policy->services[i] != NULL && rc == 0; i++)
            rc = audit_one(rpcs, policy->services[i], report);

        return rc;
    }

    /* No explicit list: audit every loaded *.service. */
    {
        te_vec units = TE_VEC_INIT(tapi_systemd_unit);
        const tapi_systemd_unit *unit;

        rc = tapi_systemd_list(rpcs, &units);
        if (rc != 0)
            return rc;

        TE_VEC_FOREACH(&units, unit)
        {
            if (!is_service(unit->name))
                continue;
            if (unit->load != NULL && strcmp(unit->load, "loaded") != 0)
                continue;
            rc = audit_one(rpcs, unit->name, report);
            if (rc != 0)
                break;
        }

        tapi_systemd_list_free(&units);
    }

    return rc;
}
