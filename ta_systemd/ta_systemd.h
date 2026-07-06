/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Agent-side systemd introspection
 *
 * Reading the systemd units of an agent and the sandbox/hardening
 * properties of its services over **libsystemd's sd-bus**
 * (@c systemd/sd-bus.h, @c -lsystemd): the library is linked into the
 * agent and the system bus is spoken in-process, nothing is spawned and
 * @c systemctl / @c systemd-analyze are not scraped. The agent and its
 * RPC server both link this; the RPCs (see systemd_rpc.x.m4) are thin
 * wrappers over these functions.
 *
 * Read-only: it queries @c org.freedesktop.systemd1 and reads
 * properties. It does not start, stop, enable or change any unit.
 *
 * Results come back as newline-separated text, one record per line with
 * tab-separated fields, the same shape tsf-usb/tsf-upnp use - the
 * engine side parses them.
 */

#ifndef __TA_SYSTEMD_H__
#define __TA_SYSTEMD_H__

#include "te_errno.h"
#include "te_string.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * List the systemd units.
 *
 * One unit per line, tab-separated:
 * @c "name\\tload\\tactive\\tsub\\tdescription", from the Manager's
 * @c ListUnits (load/active/sub are the unit's load, active and sub
 * states).
 *
 * @param[out] count    Number of units.
 * @param[out] result   The unit lines.
 *
 * @return Status code.
 */
extern te_errno ta_systemd_list(int *count, te_string *result);

/**
 * Read a service unit's sandbox/hardening properties.
 *
 * One property per line, @c "key\\tvalue", for the keys a security
 * review cares about: @c NoNewPrivileges, @c ProtectSystem,
 * @c ProtectHome, @c PrivateTmp, @c PrivateDevices,
 * @c ProtectKernelModules, @c ProtectKernelTunables, @c DynamicUser
 * (booleans as @c 0 / @c 1), @c User (a string), @c CapabilityBoundingSet,
 * @c AmbientCapabilities, @c RestrictNamespaces (unsigned decimal
 * bitmasks), and @c SystemCallFilterCount, @c RestrictAddressFamiliesCount
 * (how many entries each filter holds; @c 0 means no filter).
 *
 * @param[in]  unit     Unit name, e.g. @c "sshd.service".
 * @param[out] result   The property lines.
 *
 * @return Status code.
 * @retval TE_ENOENT    There is no such unit.
 */
extern te_errno ta_systemd_props(const char *unit, te_string *result);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TA_SYSTEMD_H__ */
