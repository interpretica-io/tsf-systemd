/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief systemd RPC server library
 *
 * The systemd_* RPCs (see systemd_rpc.x.m4) on top of ta_systemd.
 * TARPC_FUNC_STATIC() binds an RPC to the function of the same name,
 * so each RPC has a plain C function first and the wrapper after it.
 */

#define TE_LGR_USER     "RPC SYSTEMD"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "rpc_server.h"

#include "ta_systemd.h"

/* Hand a te_string result over to an RPC string field (never NULL). */
static char *
take(te_string *str)
{
    return str->ptr != NULL ? str->ptr : TE_STRDUP("");
}

static te_errno
systemd_list(int *count, char **result)
{
    te_string r = TE_STRING_INIT;
    te_errno rc = ta_systemd_list(count, &r);

    *result = take(&r);
    return rc;
}

TARPC_FUNC_STATIC(systemd_list, {},
{
    int count = 0;

    MAKE_CALL(out->retval = func(&count, &out->result));
    out->count = count;
    out->common.errno_changed = false;
})

static te_errno
systemd_props(const char *unit, char **result)
{
    te_string r = TE_STRING_INIT;
    te_errno rc = ta_systemd_props(unit, &r);

    *result = take(&r);
    return rc;
}

TARPC_FUNC_STATIC(systemd_props, {},
{
    MAKE_CALL(out->retval = func(in->unit, &out->result));
    out->common.errno_changed = false;
})
