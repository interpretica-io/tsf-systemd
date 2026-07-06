/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief systemd TAPI: RPC client wrappers
 *
 * Client wrappers of the systemd_* RPCs, see systemd_rpc.x.m4. Tests use
 * tapi_systemd.h; these are the calls behind it, one per RPC.
 */

#ifndef __TAPI_SYSTEMD_RPC_H__
#define __TAPI_SYSTEMD_RPC_H__

#include "te_errno.h"
#include "te_string.h"
#include "rcf_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * List the agent's systemd units (raw record text).
 *
 * @param[in]  rpcs     RPC server on the agent.
 * @param[out] count    Number of units, or @c NULL.
 * @param[out] result   The unit lines, or @c NULL.
 *
 * @return Status code.
 */
extern te_errno rpc_systemd_list(rcf_rpc_server *rpcs, int *count,
                                 te_string *result);

/**
 * Read a service unit's hardening properties (raw key/value text).
 *
 * @param[in]  rpcs     RPC server on the agent.
 * @param[in]  unit     Unit name, e.g. @c "sshd.service".
 * @param[out] result   The property lines, or @c NULL.
 *
 * @return Status code.
 */
extern te_errno rpc_systemd_props(rcf_rpc_server *rpcs, const char *unit,
                                  te_string *result);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_SYSTEMD_RPC_H__ */
