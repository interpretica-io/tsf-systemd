# tsf-systemd

Reading the systemd state and service hardening of a Test Agent,
packaged as an external Test Environment (TE) repository (consumed with
the `TE_EXT_REPO` builder directive). It reads over a low-level C
library — **libsystemd's sd-bus, no `systemctl` scraping** — for both an
inventory and a security posture.

Three libraries:

- `ta_systemd` — agent side. Over **libsystemd's sd-bus**
  (`systemd/sd-bus.h`, `-lsystemd`): list the units (the Manager's
  `ListUnits`) with their load/active/sub state, and read a service's
  sandbox/hardening properties off `org.freedesktop.systemd1` (e.g.
  `NoNewPrivileges`, `ProtectSystem`, `CapabilityBoundingSet`,
  `SystemCallFilter`). Read-only — it starts, stops and changes nothing.
  The agent and its RPC server both link it.
- `rpcs_systemd` — the `systemd_*` RPCs for the agent's RPC server, thin
  wrappers over `ta_systemd`.
- `tapi_systemd` — engine side. `tapi_systemd.h` lists units into a
  `tapi_systemd_unit` vector and reads a service's hardening into a
  `tapi_systemd_hardening`; `tapi_systemd_audit.h` reads a set of
  services as a hardening posture through tsf-cybersec;
  `tapi_systemd_rpc.h` is the one-per-RPC layer beneath.

TE has no systemd introspection of its own.

## What it reads

```c
tapi_systemd_hardening h;

CHECK_RC(tapi_systemd_hardening(rpcs, "sshd.service", &h));
RING("NoNewPrivileges=%d ProtectSystem=%s caps=0x%llx",
     h.no_new_privileges,
     h.protect_system != NULL ? h.protect_system : "?",
     (unsigned long long)h.capability_bounding_set);
tapi_systemd_hardening_free(&h);
```

`tapi_systemd_list()` snapshots every unit (name, load/active/sub state,
description). `tapi_systemd_hardening()` reads one service's exec-context
knobs: `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `PrivateTmp`,
`PrivateDevices`, `ProtectKernelModules`, `ProtectKernelTunables`,
`DynamicUser`, `User`, `CapabilityBoundingSet`, `AmbientCapabilities`,
`RestrictNamespaces`, and the entry counts of `SystemCallFilter` and
`RestrictAddressFamilies`.

## The library is linked, not a program

`ta_systemd` does not run `systemctl show` or `systemd-analyze security`
and parse the output. It opens the system bus with `sd_bus_open_system()`
and calls `ListUnits` and the `sd_bus_get_property*` helpers in the
agent's RPC server process, reading each property as its real D-Bus
type. Across the RPC a unit comes back as a tab-separated record and a
service's properties as `key<TAB>value` lines, which the engine side
parses.

## Security posture

`tapi_systemd_audit()` reads a set of services (a given list, or every
loaded `*.service` by default) and reports through tsf-cybersec's
finding model. It is the systemd-side complement of tsf-kernel's kernel
hardening and tsf-container's container audit.

| Finding | Severity | Raised when |
|---|---|---|
| `systemd.service-present` | info | the service exists (one per service) |
| `systemd.caps-unrestricted` | high | `CapabilityBoundingSet` is unbounded or holds `CAP_SYS_ADMIN` |
| `systemd.no-new-privileges-off` | medium | `NoNewPrivileges` is not set |
| `systemd.no-filesystem-protection` | medium | `ProtectSystem` and `ProtectHome` are both off |
| `systemd.syscalls-unfiltered` | low | there is no `SystemCallFilter` |
| `systemd.runs-as-root` | low | runs as root with no `NoNewPrivileges` |
| `systemd.not-assessed` | info | the service could not be read |

A finding's subject is the unit name (e.g. `sshd.service`), stable
between runs.

## Agent host requirements

- **libsystemd** with its development headers (Debian:
  `apt install libsystemd-dev`), and a running **systemd** as PID 1 (the
  bus call is to `org.freedesktop.systemd1`).
- Reading a service's properties needs access to the system bus; the
  default policy allows reads for any local user, so no privilege is
  required for the posture.

## Usage

Declare the repository in an external libraries catalog and pass it to
`dispatcher.sh --external=<catalog.yml>`:

```yaml
repositories:
  - name: tsf_systemd
    url: https://github.com/interpretica-io/tsf-systemd.git
    ref: <tag>
    libs:
      - ta_systemd
      - rpcs_systemd
      - tapi_systemd
```

In `builder.conf`, bind `tapi_systemd` to the engine, list `ta_systemd`
and `rpcs_systemd` among the RPC server's libraries, and add the RPC
definitions to both platforms:

```
TE_EXT_REPO_USE([tsf_systemd], [ta_systemd rpcs_systemd], [tapi_systemd])

TE_LIB_PARMS([rpcxdr], [${TE_HOST}], [],
             [--with-rpcdefs=tarpc_job.x.m4,../ta_systemd/systemd_rpc.x.m4])
TE_LIB_PARMS([rpcxdr], [${TE_TA_TYPE}], [],
             [--with-rpcdefs=tarpc_job.x.m4,../ta_systemd/systemd_rpc.x.m4])
```

`tapi_systemd_audit` reports through tsf-cybersec, so that repository
(and its prerequisites, tsf-kernel and tsf-devtool) must be built too.
The RPC program number is **35** (20–34 are taken by the other tsf
agent RPCs); change it in `systemd_rpc.x.m4` if it ever collides.

## What was verified, and what was not

**Nothing was compiled here.** libsystemd / sd-bus is Linux-only and is
not present on this build host, so — unlike tsf-usb (whose libusb calls
were syntax-checked against the installed library) — `ta_systemd.c`
could **not** be compiled or `-fsyntax-only`'d. The sd-bus usage
(`sd_bus_open_system`, `sd_bus_call_method` for `ListUnits`, the
`sd_bus_get_property*` helpers, and the `(bas)` container walk for the
filters) was written against the documented sd-bus API; the engine side,
the RPCs and the meson/`TE_EXT_REPO` wiring follow the tsf-usb template
unbuilt. The first suite to build tsf-systemd should expect the ordinary
first-build fixes — in particular confirm the `SystemCallFilter` /
`RestrictAddressFamilies` property signature (`(bas)`) against the
systemd version on the agent.

## Scope

- **Read-only.** tsf-systemd lists units and reads properties. It does
  not start, stop, enable, disable, mask or reload any unit.
- **Posture is about defaults vs. hardening.** A finding means a service
  runs without a particular systemd sandbox knob; whether that matters
  depends on what the service does. The audit reports; the test decides
  what to fail on.
