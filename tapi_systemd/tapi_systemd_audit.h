/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief What a service's systemd sandboxing is worth as a posture
 *
 * @defgroup tapi_systemd_audit systemd hardening posture
 * @ingroup tapi_systemd
 * @{
 *
 * A set of services read as a sandboxing posture and reported through
 * tsf-cybersec: for each service, whether systemd's own hardening knobs
 * are turned on - NoNewPrivileges, a filesystem protection, a trimmed
 * capability set, a system-call filter - or whether the unit runs with
 * the defaults, which is to say unconfined.
 *
 * This only reads properties over the bus; it changes no unit. It is
 * the systemd-side complement of tsf-kernel's kernel hardening and
 * tsf-container's container audit.
 *
 * | Finding | Severity | Raised when |
 * |---|---|---|
 * | @c systemd.service-present | info | the service exists (one per service) |
 * | @c systemd.caps-unrestricted | high | CapabilityBoundingSet is unbounded or holds CAP_SYS_ADMIN |
 * | @c systemd.no-new-privileges-off | medium | NoNewPrivileges is not set |
 * | @c systemd.no-filesystem-protection | medium | ProtectSystem and ProtectHome are both off |
 * | @c systemd.syscalls-unfiltered | low | there is no SystemCallFilter |
 * | @c systemd.runs-as-root | low | runs as root with no sandboxing |
 * | @c systemd.not-assessed | info | the service could not be read |
 *
 * A finding's subject is the unit name (e.g. @c "sshd.service"), stable
 * between runs.
 */

#ifndef __TAPI_SYSTEMD_AUDIT_H__
#define __TAPI_SYSTEMD_AUDIT_H__

#include "te_errno.h"
#include "rcf_rpc.h"

#include "tapi_cybersec.h"

#ifdef __cplusplus
extern "C" {
#endif

/** What services to audit, and how. */
typedef struct tapi_systemd_audit_policy {
    /**
     * @c NULL-terminated list of service unit names to audit, or
     * @c NULL to audit every loaded @c *.service the agent lists.
     */
    const char *const *services;
} tapi_systemd_audit_policy;

/**
 * The default: audit every loaded @c *.service on the agent.
 */
extern const tapi_systemd_audit_policy tapi_systemd_default_audit_policy;

/**
 * Read a set of services' hardening posture into @p report.
 *
 * @param[in]  rpcs     RPC server on the agent.
 * @param[in]  policy   Which services, or @c NULL for the default.
 * @param[out] report   Report to append findings to.
 *
 * @return Status code of reading the posture, not its verdict.
 */
extern te_errno tapi_systemd_audit(rcf_rpc_server *rpcs,
                                   const tapi_systemd_audit_policy *policy,
                                   tapi_cybersec_report *report);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_SYSTEMD_AUDIT_H__ */

/**@} <!-- END tapi_systemd_audit --> */
