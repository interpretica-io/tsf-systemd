/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Reading systemd units and service hardening from a test
 *
 * @defgroup tapi_systemd systemd (tapi_systemd)
 * @{
 *
 * Reading the systemd state of a Test Agent over libsystemd's sd-bus in
 * the agent's RPC server (not by scraping @c systemctl): the units that
 * exist and their state, and, for a service, the sandbox/hardening
 * properties of its exec context. Read-only - it starts, stops and
 * changes nothing.
 *
 * - tapi_systemd_list() snapshots every unit into a vector of
 *   #tapi_systemd_unit;
 * - tapi_systemd_hardening() reads one service's hardening properties
 *   into a #tapi_systemd_hardening;
 * - @ref tapi_systemd_audit (tapi_systemd_audit.h) reads a set of
 *   services as a hardening posture through tsf-cybersec.
 *
 * @code
 * tapi_systemd_hardening h;
 *
 * CHECK_RC(tapi_systemd_hardening(rpcs, "sshd.service", &h));
 * RING("NoNewPrivileges=%d ProtectSystem=%s", h.no_new_privileges,
 *      h.protect_system != NULL ? h.protect_system : "?");
 * tapi_systemd_hardening_free(&h);
 * @endcode
 */

#ifndef __TAPI_SYSTEMD_H__
#define __TAPI_SYSTEMD_H__

#include <stdint.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "rcf_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** One systemd unit as listed on the agent. */
typedef struct tapi_systemd_unit {
    /** Unit name, e.g. @c "sshd.service". */
    char *name;
    /** Load state, e.g. @c "loaded". */
    char *load;
    /** Active state, e.g. @c "active". */
    char *active;
    /** Sub state, e.g. @c "running". */
    char *sub;
    /** Human-readable description. */
    char *description;
} tapi_systemd_unit;

/**
 * The sandbox/hardening properties of one service unit. Booleans default
 * to @c false, strings to @c NULL and counts to @c 0 when a property was
 * not reported - the conservative "not hardened" reading.
 */
typedef struct tapi_systemd_hardening {
    /** The unit this describes. */
    char *unit;
    /** Whether anything was read at all (the service exists). */
    bool present;
    /** @c NoNewPrivileges. */
    bool no_new_privileges;
    /** @c ProtectSystem: @c "no"/"yes"/"full"/"strict", or @c NULL. */
    char *protect_system;
    /** @c ProtectHome: @c "no"/"yes"/"read-only"/"tmpfs", or @c NULL. */
    char *protect_home;
    /** @c PrivateTmp. */
    bool private_tmp;
    /** @c PrivateDevices. */
    bool private_devices;
    /** @c ProtectKernelModules. */
    bool protect_kernel_modules;
    /** @c ProtectKernelTunables. */
    bool protect_kernel_tunables;
    /** @c DynamicUser. */
    bool dynamic_user;
    /** @c User the service runs as, or @c NULL (i.e. root). */
    char *user;
    /** @c CapabilityBoundingSet (bitmask of capabilities). */
    uint64_t capability_bounding_set;
    /** @c AmbientCapabilities. */
    uint64_t ambient_capabilities;
    /** @c RestrictNamespaces (bitmask; 0 means no restriction). */
    uint64_t restrict_namespaces;
    /** Number of @c SystemCallFilter entries (0 means no filter). */
    int syscall_filter_count;
    /** Number of @c RestrictAddressFamilies entries (0 means none). */
    int restrict_address_families_count;
} tapi_systemd_hardening;

/** The capability number of @c CAP_SYS_ADMIN (bit in the cap bitmask). */
#define TAPI_SYSTEMD_CAP_SYS_ADMIN 21

/**
 * Snapshot the agent's systemd units.
 *
 * @param[in]  rpcs     RPC server on the agent.
 * @param[out] units    Vector of #tapi_systemd_unit; release with
 *                      tapi_systemd_list_free().
 *
 * @return Status code.
 */
extern te_errno tapi_systemd_list(rcf_rpc_server *rpcs, te_vec *units);

/**
 * Read one service unit's hardening properties.
 *
 * @param[in]  rpcs     RPC server on the agent.
 * @param[in]  unit     Unit name, e.g. @c "sshd.service".
 * @param[out] out      Hardening to fill; release with
 *                      tapi_systemd_hardening_free().
 *
 * @return Status code.
 * @retval TE_ENOENT    There is no such unit.
 */
extern te_errno tapi_systemd_hardening(rcf_rpc_server *rpcs,
                                       const char *unit,
                                       tapi_systemd_hardening *out);

/**
 * Does a capability bitmask include a capability?
 *
 * @param mask      A @c CapabilityBoundingSet / @c AmbientCapabilities.
 * @param cap       A capability number (e.g. #TAPI_SYSTEMD_CAP_SYS_ADMIN).
 *
 * @return @c true when the bit is set.
 */
extern bool tapi_systemd_cap_has(uint64_t mask, unsigned int cap);

/**
 * Write one unit into the log.
 *
 * @param unit      Unit.
 */
extern void tapi_systemd_unit_log(const tapi_systemd_unit *unit);

/**
 * Release a unit snapshot.
 *
 * @param units     Vector from tapi_systemd_list().
 */
extern void tapi_systemd_list_free(te_vec *units);

/**
 * Release a hardening record.
 *
 * @param h         Hardening.
 */
extern void tapi_systemd_hardening_free(tapi_systemd_hardening *h);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_SYSTEMD_H__ */

/**@} <!-- END tapi_systemd --> */
