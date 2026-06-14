"""VMware vSphere log simulator (vCenter management plane + ESXi hypervisor).

Ports the legacy ``cloud-mgr`` and ``hypervisor`` generators onto the shared
core, using real VMware component and wire conventions instead of the
Fabrikam-branded approximations. ONE coherent estate drives every line -
1 vCenter, 6-8 ESXi hosts, 40-60 VMs pinned to those hosts, datastores with
``naa.6006016...`` ids - so vCenter task events and ESXi host messages
reference the SAME vm-ids and hosts. That correlation is the demo value.

Both planes emit RFC 5424 syslog (facility local0):

  vCenter (vpxd):
    <134>1 2026-01-15T12:00:00.123Z vcenter-01.corp.example.com vpxd 12345 - -
      [Originator@6876 sub=vpxLro opID=ab12c-04] [VpxLRO] -- BEGIN task-4821 --
      vm-118 -- vim.VirtualMachine.PowerOnVM_Task -- 52a1b8c9-1a2b-...
    ...later the matching FINISH line (same task id + opID, success|error),
    paired exactly like the ASA build/teardown table. Plus user login/logout
    (sub=Default), DRS migration recommendations, vSphere HA events, and alarm
    transitions (sub=AlarmManager).

  ESXi host (vmkernel / hostd / vpxa / vobd):
    <134>1 2026-01-15T12:00:00.123Z esx-host-03.corp.example.com vmkernel - - -
      cpu7:2098765)ScsiDeviceIO: 3024: Cmd(0x45a2f1) 0x28 to dev
      "naa.60060160123456789abcdef012345678" failed H:0x0 D:0x2 P:0x0
      Valid sense data: 0x5 0x24 0x0

  NAA device ids are real Type-6 (IEEE Registered Extended, 128-bit) - the
  'naa.6006016' prefix plus a 25-hex tail, 32 hex digits total. SCSI sense
  varies per line and reflects the failure mode (connectivity / not-ready in
  the host-failure cascade, generic transient errors otherwise).

Formats (--format): vcenter | esxi | both (default both).

Scenarios (--scenario):
  host-failure  recurring windows where ONE ESXi host cascades vmkernel storage
                / connectivity errors plus a vobd 'Lost access' VOB, while
                vCenter logs the correlated response: a host-connection alarm
                goes red and vSphere HA restarts that host's VMs on other hosts
                - the classic correlated infrastructure-incident demo. Both
                planes name that host by the SAME FQDN, and the cascade's SCSI
                sense reflects connectivity loss (NO_CONNECT / NOT READY), never
                ILLEGAL REQUEST.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime

from log_simulators.core import (
    BurstSchedule,
    EventFn,
    RunConfig,
    base_parser,
    config_from_args,
    hostnames,
    make_faker,
    pick,
    pri,
    rfc5424_ts,
    run,
    zipf_weights,
)

# Syslog facility/severity. ESXi and vCenter remote syslog both forward on a
# single facility (local0 here); severity carries the message's real weight.
FACILITY = 16  # local0
INFO, WARNING, ERR = 6, 4, 3

VCENTER_HOST = "vcenter-01.corp.example.com"
DOMAIN = "corp.example.com"
MAX_OPEN_TASKS = 64

# Real vim.VirtualMachine task verbs, weighted to a power-op-heavy mix.
TASK_VERBS = [
    "PowerOnVM_Task",
    "PowerOffVM_Task",
    "MigrateVM_Task",  # vMotion
    "RelocateVM_Task",  # storage vMotion
    "CloneVM_Task",
    "ReconfigVM_Task",
    "CreateSnapshot_Task",
    "RemoveSnapshot_Task",
]
TASK_VERB_WEIGHTS = [26.0, 20.0, 16.0, 8.0, 5.0, 12.0, 7.0, 6.0]

VM_ROLES = ["prod-web", "prod-app", "db", "cache", "infra", "test"]
VM_ROLE_WEIGHTS = [30.0, 24.0, 18.0, 12.0, 9.0, 7.0]

DATASTORE_NAMES = [
    "DS-SSD-01",
    "DS-SSD-02",
    "DS-NFS-prod-01",
    "DS-NFS-prod-02",
    "vsanDatastore",
    "DS-iSCSI-01",
    "DS-Capacity-01",
]
CLIENTS = [
    "VMware vSphere Client/8.0.2",
    "pyvmomi Python/3.10.4",
    "govc/0.36.1",
    "VMware PowerCLI/13.1.0",
    "vami-sso/8.0",
]
# Benign alarm names only - 'Host connection and power state' is reserved for
# the host-failure scenario so the red transition stays unambiguous.
ALARM_NAMES = [
    "Host memory usage",
    "Host CPU usage",
    "Virtual machine CPU usage",
    "Virtual machine memory usage",
    "Datastore usage on disk",
    "Network uplink redundancy lost",
]

HEX = "0123456789abcdef"

# SCSI completion status + sense, as ESXi vmkernel renders a failed I/O:
#   "failed H:<host> D:<device> P:<plugin> <Valid|Possible> sense data: <key> <asc> <ascq>"
# Two pools, chosen per line via cfg.content_rng() so the sense is not byte-identical
# across storage errors (one repeated tuple is a tell of a synthetic log).
#
# Connectivity / path-loss pool - used when a host is LOSING ACCESS to its storage
# (the host-failure scenario): NO_CONNECT transport failures (H:0x1) and NOT READY /
# target-down / hardware sense (D:0x2, key 0x2/0x4). Never ILLEGAL REQUEST (0x5/0x24),
# which would wrongly imply a malformed CDB rather than a vanished path.
CONNECTIVITY_SENSE = [
    "H:0x1 D:0x0 P:0x0 Possible sense data: 0x0 0x0 0x0",  # NO_CONNECT: path down
    "H:0x0 D:0x2 P:0x0 Valid sense data: 0x2 0x4 0x3",  # NOT READY: LUN not ready
    "H:0x0 D:0x2 P:0x0 Valid sense data: 0x2 0x4 0x0",  # NOT READY: not reportable
    "H:0x0 D:0x2 P:0x0 Valid sense data: 0x2 0x4 0x2",  # NOT READY: initializing
    "H:0x0 D:0x2 P:0x0 Valid sense data: 0x4 0x44 0x0",  # HARDWARE ERROR: target
]

# Generic transient-error pool - sporadic non-scenario storage blips: an illegal CDB
# field, an aborted command, a unit-attention after a reset, a recovered error.
GENERIC_SENSE = [
    "H:0x0 D:0x2 P:0x0 Valid sense data: 0x5 0x24 0x0",  # ILLEGAL REQUEST: bad CDB
    "H:0x0 D:0x2 P:0x0 Valid sense data: 0xb 0x0 0x0",  # ABORTED COMMAND
    "H:0x0 D:0x2 P:0x0 Valid sense data: 0x6 0x29 0x0",  # UNIT ATTENTION: reset
    "H:0x0 D:0x2 P:0x0 Valid sense data: 0x1 0x18 0x0",  # RECOVERED ERROR: retries
]

Datastore = tuple[str, str, str]  # (name, naa id, volume uuid)


@dataclass
class TaskState:
    moref: str
    method: str
    opid: str


def build_event_fn(cfg: RunConfig, args: argparse.Namespace) -> EventFn:
    rng = cfg.content_rng()
    fk = make_faker(cfg.seed)
    fmt: str = args.format

    # --- estate (built once, seeded) -------------------------------------
    num_hosts = rng.randint(6, 8)
    host_short = hostnames(rng, num_hosts, "esx-host")  # esx-host-01 ...
    host_fqdn = {hs: f"{hs}.{DOMAIN}" for hs in host_short}
    host_weights = zipf_weights(num_hosts, s=0.6)
    vpxd_pid = rng.randint(2000, 9000)

    num_vms = rng.randint(40, 60)
    vm_morefs: list[str] = []
    vm_display: dict[str, str] = {}
    vm_host: dict[str, str] = {}
    role_counts = dict.fromkeys(VM_ROLES, 0)
    moref_num = rng.randint(100, 400)
    for i in range(num_vms):
        moref = f"vm-{moref_num}"
        moref_num += 1
        role = pick(rng, VM_ROLES, VM_ROLE_WEIGHTS)
        role_counts[role] += 1
        vm_display[moref] = f"{role}-{role_counts[role]:02d}"
        vm_host[moref] = host_short[i % num_hosts]  # round-robin pin
        vm_morefs.append(moref)
    vm_weights = zipf_weights(num_vms, s=0.7)
    vms_on_host: dict[str, list[str]] = {}
    for moref, hs in vm_host.items():
        vms_on_host.setdefault(hs, []).append(moref)

    num_ds = rng.randint(5, len(DATASTORE_NAMES))
    datastores: list[Datastore] = []
    for name in DATASTORE_NAMES[:num_ds]:
        # NAA Type-6 (IEEE Registered Extended) ids are 128-bit = 32 hex digits.
        # Prefix '6006016' is 7 digits, so the random tail is 25 -> 32 total.
        naa = "naa.6006016" + "".join(rng.choices(HEX, k=25))  # 7 + 25 = 32 hex
        vol = "-".join(
            (
                f"{rng.getrandbits(32):08x}",
                f"{rng.getrandbits(32):08x}",
                f"{rng.getrandbits(16):04x}",
                f"{rng.getrandbits(48):012x}",
            )
        )
        datastores.append((name, naa, vol))
    ds_weights = zipf_weights(len(datastores), s=0.5)

    principals = [
        "VSPHERE.LOCAL\\Administrator",
        "administrator@vsphere.local",
        *(f"svc-{fk.user_name()}@{DOMAIN}" for _ in range(3)),
        *(f"{fk.user_name()}@{DOMAIN}" for _ in range(4)),
    ]
    principal_weights = zipf_weights(len(principals), s=0.7)
    esxi_principal = "root@127.0.0.1"

    # --- scenario state ---------------------------------------------------
    burst = BurstSchedule(period=600, length=60) if args.scenario == "host-failure" else None
    failing_host = pick(rng, host_short, host_weights)
    failing_ds: Datastore = pick(rng, datastores, ds_weights)
    failing_vms = vms_on_host.get(failing_host) or [vm_morefs[0]]
    other_hosts = [hs for hs in host_short if hs != failing_host]

    next_task = rng.randint(1000, 9000)
    next_event = rng.randint(100_000, 900_000)
    open_tasks: dict[str, TaskState] = {}

    # --- small helpers ----------------------------------------------------
    def opid() -> str:
        return f"{rng.randrange(16**5):05x}-{rng.randint(0, 99):02d}"

    def session_uuid() -> str:
        return "-".join(
            (
                f"{rng.getrandbits(32):08x}",
                f"{rng.getrandbits(16):04x}",
                f"{rng.getrandbits(16):04x}",
                f"{rng.getrandbits(16):04x}",
                f"{rng.getrandbits(48):012x}",
            )
        )

    def vcenter_env(ts: datetime, sub: str, op: str, body: str, sev: int) -> str:
        return (
            f"<{pri(FACILITY, sev)}>1 {rfc5424_ts(ts)} {VCENTER_HOST} vpxd {vpxd_pid} - - "
            f"[Originator@6876 sub={sub} opID={op}] {body}"
        )

    def esxi_env(ts: datetime, hs: str, app: str, body: str, sev: int) -> str:
        return f"<{pri(FACILITY, sev)}>1 {rfc5424_ts(ts)} {host_fqdn[hs]} {app} - - - {body}"

    # --- vCenter (vpxd) generators ---------------------------------------
    def begin_task(ts: datetime) -> str:
        nonlocal next_task
        moref = pick(rng, vm_morefs, vm_weights)
        method = f"vim.VirtualMachine.{pick(rng, TASK_VERBS, TASK_VERB_WEIGHTS)}"
        op = opid()
        tid = f"task-{next_task}"
        next_task += 1
        open_tasks[tid] = TaskState(moref, method, op)
        body = f"[VpxLRO] -- BEGIN {tid} -- {moref} -- {method} -- {session_uuid()}"
        return vcenter_env(ts, "vpxLro", op, body, INFO)

    def finish_task(ts: datetime, tid: str) -> str:
        st = open_tasks.pop(tid)
        ok = rng.random() < 0.88
        result = "success" if ok else "error"
        body = f"[VpxLRO] -- FINISH {tid} -- {st.moref} -- {st.method} -- {result}"
        return vcenter_env(ts, "vpxLro", st.opid, body, INFO if ok else ERR)

    def login_event(ts: datetime) -> str:
        pr = pick(rng, principals, principal_weights)
        client = rng.choice(CLIENTS)
        if rng.random() < 0.6:
            body = f"User {pr} logged in as {client}"
        else:
            body = f"User {pr} logged out ({client})"
        return vcenter_env(ts, "Default", opid(), body, INFO)

    def drs_event(ts: datetime) -> str:
        moref = pick(rng, vm_morefs, vm_weights)
        src = vm_host[moref]
        dest = rng.choice([hs for hs in host_short if hs != src])
        # vCenter renders one consistent inventory name per host - the FQDN, same as
        # the ESXi syslog hostname - so a host-name join across planes succeeds.
        body = (
            f"DRS-recommended migration of {vm_display[moref]} ({moref}) "
            f"from {host_fqdn[src]} to {host_fqdn[dest]}"
        )
        return vcenter_env(ts, "Default", opid(), body, INFO)

    def alarm_event(ts: datetime) -> str:
        name = rng.choice(ALARM_NAMES)
        if rng.random() < 0.5:
            entity = host_fqdn[pick(rng, host_short, host_weights)]  # FQDN: match ESXi plane
        else:
            entity = vm_display[pick(rng, vm_morefs, vm_weights)]
        old, new, sev = rng.choice(
            [
                ("green", "yellow", WARNING),
                ("yellow", "green", INFO),
                ("gray", "green", INFO),
                ("green", "gray", INFO),
                ("yellow", "red", ERR),
                ("red", "yellow", WARNING),
            ]
        )
        return vcenter_env(
            ts, "AlarmManager", opid(), f"Alarm '{name}' on {entity}: {old} -> {new}", sev
        )

    def ha_event(ts: datetime) -> str:
        hs = pick(rng, host_short, host_weights)
        status = rng.choice(["Green", "Green", "Green", "Yellow"])
        body = f"vSphere HA agent for host {host_fqdn[hs]} has an operational status of {status}"
        return vcenter_env(ts, "Default", opid(), body, INFO if status == "Green" else WARNING)

    def vcenter_normal(ts: datetime) -> str:
        if len(open_tasks) >= MAX_OPEN_TASKS:
            return finish_task(ts, next(iter(open_tasks)))
        roll = rng.random()
        if roll < 0.55:
            if not open_tasks or rng.random() < 0.55:
                return begin_task(ts)
            return finish_task(ts, rng.choice(list(open_tasks)))
        if roll < 0.70:
            return login_event(ts)
        if roll < 0.82:
            return drs_event(ts)
        if roll < 0.93:
            return alarm_event(ts)
        return ha_event(ts)

    # --- ESXi host generators --------------------------------------------
    def vmkernel_storage_error(
        ts: datetime, hs: str, ds: Datastore | None = None, *, connectivity: bool = False
    ) -> str:
        _, naa, _ = ds if ds is not None else pick(rng, datastores, ds_weights)
        # A host losing access to storage reports NO_CONNECT / NOT READY sense; the
        # sporadic background blip reports a generic transient error. Pick per line so
        # the sense varies instead of repeating one hardcoded tuple.
        sense = rng.choice(CONNECTIVITY_SENSE if connectivity else GENERIC_SENSE)
        body = (
            f"cpu{rng.randint(0, 31)}:{rng.randint(2_097_152, 2_200_000)})ScsiDeviceIO: "
            f"{rng.randint(1000, 9999)}: Cmd(0x{rng.getrandbits(24):06x}) 0x28 to dev "
            f'"{naa}" failed {sense}'
        )
        return esxi_env(ts, hs, "vmkernel", body, WARNING)

    def vmkernel_benign(ts: datetime, hs: str) -> str:
        cpu = rng.randint(0, 31)
        world = rng.randint(2_097_152, 2_200_000)
        code = rng.randint(1000, 9999)
        roll = rng.random()
        if roll < 0.4:
            _, naa, _ = pick(rng, datastores, ds_weights)
            body = f"cpu{cpu}:{world})NMP: {code}: last reservation state from device {naa} cleared"
        elif roll < 0.7:
            body = (
                f"cpu{cpu}:{world})VSCSI: {code}: handle "
                f"{rng.randint(8000, 9000)}(vscsi0:0): Creating Virtual Device"
            )
        else:
            body = (
                f"cpu{cpu}:{world})Net: {code}: vmnic{rng.randint(0, 3)}: device link state is up"
            )
        return esxi_env(ts, hs, "vmkernel", body, INFO)

    def hostd_event(ts: datetime, hs: str) -> str:
        nonlocal next_event
        ev = next_event
        next_event += 1
        roll = rng.random()
        if roll < 0.45:
            body = f"Event {ev} : User {esxi_principal} logged in as {rng.choice(CLIENTS)}"
        elif roll < 0.70:
            body = f"Event {ev} : User {esxi_principal} logged out ({rng.choice(CLIENTS)})"
        else:
            moref = rng.choice(vms_on_host.get(hs) or vm_morefs)
            state = rng.choice(["powered on", "powered off", "suspended"])
            body = f"Event {ev} : {vm_display[moref]} on {hs} in ha-datacenter is {state}"
        return esxi_env(ts, hs, "hostd", body, INFO)

    def vpxa_event(ts: datetime, hs: str) -> str:
        roll = rng.random()
        if roll < 0.5:
            body = "Completed callback"
        elif roll < 0.8:
            moref = rng.choice(vms_on_host.get(hs) or vm_morefs)
            verb = pick(rng, TASK_VERBS, TASK_VERB_WEIGHTS)
            body = (
                f"[VpxaHalCnxHostagent] Completed callback for vim.VirtualMachine.{verb} on {moref}"
            )
        else:
            moref = rng.choice(vms_on_host.get(hs) or vm_morefs)
            body = f"[VpxaInvtVm] Got SyncSet from vpxd for VM {moref}"
        return esxi_env(ts, hs, "vpxa", body, INFO)

    def vobd_event(ts: datetime, hs: str) -> str:
        name, naa, vol = pick(rng, datastores, ds_weights)
        roll = rng.random()
        if roll < 0.65:
            body = (
                f"Device {naa} performance has deteriorated. I/O latency increased "
                f"from average value of {rng.randint(500, 3000)} microseconds to "
                f"{rng.randint(20_000, 90_000)} microseconds."
            )
            return esxi_env(ts, hs, "vobd", body, WARNING)
        if roll < 0.85:
            body = (
                f"Device {naa} performance has improved. I/O latency reduced from "
                f"{rng.randint(20_000, 90_000)} microseconds to "
                f"{rng.randint(500, 3000)} microseconds."
            )
            return esxi_env(ts, hs, "vobd", body, INFO)
        return esxi_env(ts, hs, "vobd", _lost_access(name, vol), ERR)

    def esxi_normal(ts: datetime) -> str:
        hs = pick(rng, host_short, host_weights)
        roll = rng.random()
        if roll < 0.45:
            if rng.random() < 0.08:
                # On the failing host during a host-failure incident even the
                # background blip is a connectivity loss, not a random CDB error.
                conn = args.scenario == "host-failure" and hs == failing_host
                return vmkernel_storage_error(ts, hs, connectivity=conn)
            return vmkernel_benign(ts, hs)
        if roll < 0.75:
            return hostd_event(ts, hs)
        if roll < 0.93:
            return vpxa_event(ts, hs)
        return vobd_event(ts, hs)

    # --- scenario lines ---------------------------------------------------
    def esxi_failure_line(ts: datetime) -> str:
        if rng.random() < 0.8:
            return vmkernel_storage_error(ts, failing_host, failing_ds, connectivity=True)
        name, _, vol = failing_ds
        return esxi_env(ts, failing_host, "vobd", _lost_access(name, vol), ERR)

    def vcenter_ha_response(ts: datetime) -> str:
        # Both the red host-connection alarm and the HA restart name hosts by FQDN,
        # byte-equal to the ESXi-plane syslog hostname, so the incident correlates
        # across planes on a plain host-name join.
        if rng.random() < 0.35:
            body = (
                f"Alarm 'Host connection and power state' on "
                f"{host_fqdn[failing_host]}: green -> red"
            )
            return vcenter_env(ts, "AlarmManager", opid(), body, ERR)
        moref = rng.choice(failing_vms)
        dest = rng.choice(other_hosts) if other_hosts else failing_host
        body = (
            f"vSphere HA restarted virtual machine {vm_display[moref]} ({moref}) "
            f"on host {host_fqdn[dest]}"
        )
        return vcenter_env(ts, "Default", opid(), body, WARNING)

    def channel() -> str:
        if fmt == "vcenter":
            return "vcenter"
        if fmt == "esxi":
            return "esxi"
        return "vcenter" if rng.random() < 0.45 else "esxi"

    def make_event(ts: datetime, seq: int) -> str:
        chan = channel()
        if (
            burst is not None
            and burst.active(ts)
            and rng.random() < 0.55 + 0.4 * burst.intensity(ts)
        ):
            return esxi_failure_line(ts) if chan == "esxi" else vcenter_ha_response(ts)
        return vcenter_normal(ts) if chan == "vcenter" else esxi_normal(ts)

    return make_event


def _lost_access(name: str, vol: str) -> str:
    return (
        f"Lost access to volume {vol} ({name}) due to connectivity issues. "
        f"Recovery attempt is in progress and outcome will be reported shortly."
    )


def main(argv: list[str] | None = None) -> int:
    parser = base_parser(
        "logsim-vmware",
        "Generate realistic VMware vSphere logs: vCenter (vpxd) task lifecycle "
        "plus ESXi host (vmkernel/hostd/vpxa/vobd) syslog from one shared estate.",
        default_rate=10.0,
    )
    parser.add_argument(
        "--format",
        choices=["vcenter", "esxi", "both"],
        default="both",
        help="which plane to emit: vCenter management, ESXi hosts, or both (default: both)",
    )
    parser.add_argument(
        "--scenario",
        choices=["none", "host-failure"],
        default="none",
        help="inject a correlated ESXi host-failure + vSphere HA incident (default: none)",
    )
    args = parser.parse_args(argv)
    cfg = config_from_args(args)
    run(cfg, build_event_fn(cfg, args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
