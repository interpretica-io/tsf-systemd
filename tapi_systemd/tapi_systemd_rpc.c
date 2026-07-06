/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief systemd TAPI: RPC client wrappers
 *
 * The rcf_rpc_call() boilerplate behind tapi_systemd. The RPCs return
 * te_errno; an RPC transport failure is mapped to TE_ECORRUPTED.
 */

#define TE_LGR_USER     "TAPI SYSTEMD RPC"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "logger_api.h"
#include "tapi_rpc_internal.h"
#include "tarpc.h"

#include "tapi_systemd_rpc.h"

#define CHECK_RPC_ERRNO_UNCHANGED(_func, _var) \
    CHECK_RETVAL_VAR_ERR_COND(_func, _var, false,                    \
                              TE_RC(TE_TAPI, TE_ECORRUPTED), false)

/* Append an RPC string result, when there is one. */
static void
take_string(te_string *dst, const char *src)
{
    if (dst != NULL && src != NULL)
        te_string_append(dst, "%s", src);
}

/* See description in tapi_systemd_rpc.h */
te_errno
rpc_systemd_list(rcf_rpc_server *rpcs, int *count, te_string *result)
{
    tarpc_systemd_list_in in;
    tarpc_systemd_list_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    rcf_rpc_call(rpcs, "systemd_list", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(systemd_list, out.retval);
    TAPI_RPC_LOG(rpcs, systemd_list, "", "%r count=%d", out.retval,
                 out.count);

    if (out.retval == 0)
    {
        if (count != NULL)
            *count = out.count;
        take_string(result, out.result);
    }
    RETVAL_TE_ERRNO(systemd_list, out.retval);
}

/* See description in tapi_systemd_rpc.h */
te_errno
rpc_systemd_props(rcf_rpc_server *rpcs, const char *unit, te_string *result)
{
    tarpc_systemd_props_in in;
    tarpc_systemd_props_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.unit = (char *)unit;

    rcf_rpc_call(rpcs, "systemd_props", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(systemd_props, out.retval);
    TAPI_RPC_LOG(rpcs, systemd_props, "%s", "%r",
                 unit != NULL ? unit : "", out.retval);

    if (out.retval == 0)
        take_string(result, out.result);
    RETVAL_TE_ERRNO(systemd_props, out.retval);
}
