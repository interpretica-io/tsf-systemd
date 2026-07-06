# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved.
#
# External TE library (see TE_EXT_REPO): engine-side TAPI for systemd
# introspection on agents, and a service-hardening posture over it.
# Built as a shared library on the engine platform. It needs the
# systemd_* RPCs in rpcxdr, so add ../ta_systemd/systemd_rpc.x.m4 to the
# rpcxdr definitions of the engine platform. The posture
# (tapi_systemd_audit) reports through tsf-cybersec, so that repository
# is required too.

if get_option('engine')
    build_lib_shared = true
endif
build_lib_static = not get_option('engine')
install_lib = install_dev

headers += files(
    'tapi_systemd.h',
    'tapi_systemd_rpc.h',
    'tapi_systemd_audit.h',
)

sources += files(
    'tapi_systemd.c',
    'tapi_systemd_rpc.c',
    'tapi_systemd_audit.c',
)

te_libs += [
    'tapi',
    'tapi_rpc',
    'rcfrpc',
    'confapi',
    'rcfapi',
    'rpcxdr',
    'tapi_cybersec',
    'logger_core',
    'tools',
]
