# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved.
#
# External TE library (see TE_EXT_REPO): agent-side systemd
# introspection over libsystemd's sd-bus (read-only). The agent and its
# RPC server both link it.

headers += files(
    'ta_systemd.h',
)

sources += files(
    'ta_systemd.c',
)

te_libs += [
    'logger_core',
    'tools',
]

# libsystemd provides sd-bus. No pkg-config on some minimal images, so
# fall back to finding the library and its header directly.
cc = meson.get_compiler('c')
systemd_dep = dependency('libsystemd', required: false)
if not systemd_dep.found()
    systemd_dep = cc.find_library('systemd', has_headers: 'systemd/sd-bus.h')
endif

deps += [
    systemd_dep,
]
