/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief RPC for systemd introspection
 *
 * The RPCs of rpcs_systemd, a thin layer over ta_systemd, which reads
 * the agent's systemd units and service hardening properties in the RPC
 * server process over libsystemd's sd-bus. Add this file to the rpcxdr
 * definitions of the engine platform and of the agent platform:
 *
 *   TE_LIB_PARMS([rpcxdr], [<platform>], [],
 *                [--with-rpcdefs=tarpc_job.x.m4,../ta_systemd/systemd_rpc.x.m4])
 *
 * No handle survives between calls: the unit list is one snapshot, and a
 * service's properties are named by unit. Results that are lists come
 * back as newline-separated text with tab-separated fields - the engine
 * side parses them, the same shape tsf-usb uses.
 */

/* systemd_list(): one line per unit (name/load/active/sub/description). */
struct tarpc_systemd_list_in {
    struct tarpc_in_arg common;
};

struct tarpc_systemd_list_out {
    struct tarpc_out_arg common;

    tarpc_int       retval;
    tarpc_int       count;
    string          result<>;
};

/* systemd_props(): a service unit's hardening properties, key\tvalue. */
struct tarpc_systemd_props_in {
    struct tarpc_in_arg common;

    string          unit<>;
};

struct tarpc_systemd_props_out {
    struct tarpc_out_arg common;

    tarpc_int       retval;
    string          result<>;
};

program systemd
{
    version ver0
    {
        RPC_DEF(systemd_list)
        RPC_DEF(systemd_props)
    } = 1;
} = 35;
