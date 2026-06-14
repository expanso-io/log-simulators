"""Industrial Control System / OT network-device syslog simulator.

Emits Cisco-IOS-style ``%FACILITY-SEVERITY-MNEMONIC`` events from the network
infrastructure of a Purdue-model plant floor: managed switches in the
cell/area zone (``cellN-sw-NN``), control-zone routers (``ctrl-rtr-NN``), and
DMZ gateways (``dmz-gw-NN``). The chatter is the realistic OT mix - link-state
changes, PTP time-sync, DHCP housekeeping, REP ring redundancy, PLC comms over
PROFINET / EtherNet/IP / MODBUS / DNP3 / IEC-104, plus the occasional login,
port scan, or cabinet over-temperature. The severity mix is deliberately
info/notice-heavy; genuinely severe events (PLC comm loss, over-temp) are rare.

The mnemonic's embedded severity digit drives BOTH the message and the syslog
PRI, so they never disagree: every line carries ``pri(SYSLOG_FACILITY, sev)``
and ``%FAC-<sev>-MNEMONIC`` with the same ``sev``. ``SYSLOG_FACILITY`` is fixed
at 23 (local7), the Cisco IOS default logging facility, so ``PRI = 23*8 + sev``
and ``PRI % 8 == sev`` for every line.

Formats (--rfc):
  5424  RFC 5424 (default): <PRI>1 TIMESTAMP HOST NETWORK-DEVICE - - - MSG
  3164  classic BSD syslog: <PRI>Mmm dd hh:mm:ss HOST NETWORK-DEVICE: MSG
where MSG is ``%FAC-<sev>-MNEMONIC: text``, e.g.
  <187>1 2026-01-15T12:00:00.123Z cell3-sw-02.plant.local NETWORK-DEVICE - - - \
%IND-3-PLC_COMM_LOSS: Lost communication with PLC at 10.20.3.40 over PROFINET

Scenarios:
  plc-comm-loss  recurring windows where ONE cell-area segment degrades: a wave
                 of %IND-3-PLC_COMM_LOSS for the PLCs behind one switch, plus
                 %PORT-5-LINK_STATE_CHANGE ...DOWN and %REP-4-LINKSTATUS
                 redundancy flaps. The recovery tail closes the loop on the same
                 victim switch: %IND-5-PLC_COMM_RESTORED AND the matching physical
                 recovery - %PORT-5-LINK_STATE_CHANGE ...UP for the port that went
                 DOWN and %REP-4-LINKSTATUS ...UP for the segment that failed -
                 the OT-incident edge-filtering demo.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from datetime import datetime

from log_simulators.core import (
    BurstSchedule,
    EventFn,
    RunConfig,
    base_parser,
    config_from_args,
    internal_ips,
    make_faker,
    pick,
    pri,
    rfc3164_ts,
    rfc5424_ts,
    run,
    usernames,
    zipf_weights,
)

# Syslog severity codes (RFC 5424 numerical values).
CRIT, ERR, WARNING, NOTICE, INFO = 2, 3, 4, 5, 6

# Fixed syslog facility: 23 = local7, the Cisco IOS default logging facility.
# Keeping it constant means PRI = 23*8 + severity, so PRI % 8 == the mnemonic's
# severity digit on every line.
SYSLOG_FACILITY = 23
APP_NAME = "NETWORK-DEVICE"

# Burst geometry for the plc-comm-loss scenario (see module docstring).
BURST_PERIOD = 600.0
BURST_LENGTH = 60.0
RECOVERY_FRACTION = 0.7  # last 30% of a burst window is the recovery phase

PROTOCOLS = ["PROFINET", "EtherNet/IP", "MODBUS", "DNP3", "IEC-104"]
PROTO_WEIGHTS = [34.0, 26.0, 18.0, 12.0, 10.0]

# Normal link-state changes are overwhelmingly UP (a healthy plant); DOWN and
# friends are the minority, which makes the scenario's DOWN wave stand out.
LINK_STATES = ["UP", "UP", "UP", "UP", "UP", "DOWN", "BLOCKING", "ERR-DISABLED"]
REP_DOWN_STATES = ["DOWN", "FAILED", "FLAPPING"]
PTP_STATES = ["SLAVE", "MASTER", "SYNCHRONIZED", "FREERUN", "UNCALIBRATED"]
LOGIN_METHODS = ["SSH", "HTTPS"]
ROLE_USERS = ["scada-admin", "plc-eng", "operator", "maintenance", "hmi-svc"]

BodyFn = Callable[[], str]
# (cisco_facility, severity, mnemonic, body_fn) - severity is the digit baked
# into the mnemonic AND the PRI; they are the same value by construction.
MsgType = tuple[str, int, str, BodyFn]


def build_event_fn(cfg: RunConfig, args: argparse.Namespace) -> EventFn:
    rng = cfg.content_rng()
    fk = make_faker(cfg.seed)

    # --- device estate (built once, recurs coherently) -------------------
    switches = [
        f"cell{cell}-sw-{idx:02d}.plant.local"
        for cell in range(1, 5)  # cells 1..4
        for idx in range(1, 3)  # 2 managed switches per cell
    ]
    routers = [f"ctrl-rtr-{i:02d}.plant.local" for i in range(1, 3)]
    gateways = [f"dmz-gw-{i:02d}.plant.local" for i in range(1, 3)]
    devices = switches + routers + gateways
    device_weights = zipf_weights(len(devices), s=0.7)  # switches dominate

    # Stable OT endpoints: PLCs/RTUs on 10.20.x.x, engineering stations on
    # 10.21.x.x. PLCs are distributed round-robin behind switches so every
    # switch (and the scenario's victim switch) owns a known set.
    plc_ips = internal_ips(rng, 40, prefix="10.20")
    eng_ips = internal_ips(rng, 12, prefix="10.21")
    plcs_by_switch: dict[str, list[str]] = {sw: [] for sw in switches}
    for i, ip in enumerate(plc_ips):
        plcs_by_switch[switches[i % len(switches)]].append(ip)

    users = ROLE_USERS + usernames(fk, 8)
    user_weights = zipf_weights(len(users))
    ports = [f"G1/{n}" for n in range(1, 25)] + [f"Gi1/0/{n}" for n in range(1, 13)]
    port_weights = zipf_weights(len(ports), s=0.5)

    # --- body generators (close over the seeded pools) -------------------
    def body_link_state() -> str:
        return f"Port {pick(rng, ports, port_weights)} changed state to {rng.choice(LINK_STATES)}"

    def body_dhcp() -> str:
        mac = ":".join(f"{rng.randint(0, 255):02x}" for _ in range(6))
        return f"Assigned address {rng.choice(eng_ips)} to {mac} on port {rng.choice(ports)}"

    def body_ptp() -> str:
        return f"PTP port {rng.choice(ports)} clock state changed to {rng.choice(PTP_STATES)}"

    def body_login_success() -> str:
        user = pick(rng, users, user_weights)
        return f"User '{user}' logged in from {rng.choice(eng_ips)} via {rng.choice(LOGIN_METHODS)}"

    def body_rep_up() -> str:
        return f"Segment {rng.randint(1, 4)} port {rng.choice(ports)} link status UP"

    def body_port_errors() -> str:
        crc = rng.randint(1, 240)
        runts = rng.randint(0, 40)
        return (
            f"{crc + runts} input errors on port {rng.choice(ports)} "
            f"({crc} CRC, {runts} runts, 0 giants)"
        )

    def body_rep_down() -> str:
        status = rng.choice(REP_DOWN_STATES)
        return f"Segment {rng.randint(1, 4)} port {rng.choice(ports)} link status {status}"

    def body_port_scan() -> str:
        proto = pick(rng, PROTOCOLS, PROTO_WEIGHTS)
        return f"Potential scan from {rng.choice(eng_ips)} to {rng.choice(plc_ips)} on {proto}"

    def body_comm_loss() -> str:
        proto = pick(rng, PROTOCOLS, PROTO_WEIGHTS)
        return f"Lost communication with PLC at {rng.choice(plc_ips)} over {proto}"

    def body_login_failed() -> str:
        user = pick(rng, users, user_weights)
        return (
            f"User '{user}' failed login from {rng.choice(eng_ips)} via {rng.choice(LOGIN_METHODS)}"
        )

    def body_comm_restored() -> str:
        proto = pick(rng, PROTOCOLS, PROTO_WEIGHTS)
        return f"Restored communication with PLC at {rng.choice(plc_ips)} over {proto}"

    def body_temp() -> str:
        temp = rng.randint(61, 78)
        return f"Cabinet over-temperature {temp}C exceeds threshold 60C on {rng.choice(switches)}"

    # Weights tuned info/notice-heavy: ~78% of lines are severity 5 (notice) or
    # 6 (info); severe events (sev <= 3) stay under ~5%.
    #
    # A (facility, mnemonic) pair has a FIXED severity in real Cisco IOS, so the
    # mnemonic's severity digit is a function of the mnemonic alone. REP link
    # status changes - up OR down - are all %REP-4-LINKSTATUS (WARNING); the
    # direction lives in the body text, never in the severity. Every distinct
    # mnemonic below therefore maps to exactly one severity digit.
    msg_types: list[MsgType] = [
        ("PORT", NOTICE, "LINK_STATE_CHANGE", body_link_state),
        ("DHCP", INFO, "ADDRESS_ASSIGN", body_dhcp),
        ("PTP", NOTICE, "SYNC", body_ptp),
        ("AUTH", NOTICE, "LOGIN_SUCCESS", body_login_success),
        ("REP", WARNING, "LINKSTATUS", body_rep_up),
        ("PORT", WARNING, "ERRORS", body_port_errors),
        ("REP", WARNING, "LINKSTATUS", body_rep_down),
        ("SEC", WARNING, "PORT_SCAN_DETECTED", body_port_scan),
        ("IND", ERR, "PLC_COMM_LOSS", body_comm_loss),
        ("AUTH", ERR, "LOGIN_FAILED", body_login_failed),
        ("IND", NOTICE, "PLC_COMM_RESTORED", body_comm_restored),
        ("ENV", CRIT, "TEMP", body_temp),
    ]
    msg_weights = [34.0, 22.0, 10.0, 9.0, 6.0, 5.0, 3.0, 2.5, 2.0, 2.0, 1.5, 0.5]

    # --- scenario state (one stable victim segment) ----------------------
    burst = (
        BurstSchedule(period=BURST_PERIOD, length=BURST_LENGTH)
        if args.scenario == "plc-comm-loss"
        else None
    )
    victim_switch = rng.choice(switches)
    victim_plcs = plcs_by_switch[victim_switch]
    victim_proto = pick(rng, PROTOCOLS, PROTO_WEIGHTS)
    victim_port = pick(rng, ports, port_weights)
    victim_segment = rng.randint(1, 4)

    def envelope(ts: datetime, host: str, severity: int, block: str) -> str:
        prival = pri(SYSLOG_FACILITY, severity)
        if args.rfc == "3164":
            return f"<{prival}>{rfc3164_ts(ts)} {host} {APP_NAME}: {block}"
        return f"<{prival}>1 {rfc5424_ts(ts)} {host} {APP_NAME} - - - {block}"

    def block(cisco_fac: str, severity: int, mnemonic: str, body: str) -> str:
        return f"%{cisco_fac}-{severity}-{mnemonic}: {body}"

    def incident_event(ts: datetime) -> str:
        # Phase within the active window: the tail is the recovery phase; the
        # rest is the comm-loss wave. Recovery mirrors the loss: PLC comms come
        # back (PLC_COMM_RESTORED) AND the physical layer that went down comes
        # back too - the victim port returns UP (%PORT-5-LINK_STATE_CHANGE) and
        # the victim ring segment returns to normal (%REP-4-LINKSTATUS ...UP),
        # all on the same victim switch / port / segment that failed.
        offset = ts.timestamp() % BURST_PERIOD
        if offset >= BURST_LENGTH * RECOVERY_FRACTION:
            roll = rng.random()
            if roll < 0.6:
                ip = rng.choice(victim_plcs)
                body = f"Restored communication with PLC at {ip} over {victim_proto}"
                return envelope(
                    ts, victim_switch, NOTICE, block("IND", NOTICE, "PLC_COMM_RESTORED", body)
                )
            if roll < 0.8:
                body = f"Port {victim_port} changed state to UP"
                return envelope(
                    ts, victim_switch, NOTICE, block("PORT", NOTICE, "LINK_STATE_CHANGE", body)
                )
            body = f"Segment {victim_segment} port {victim_port} link status UP"
            return envelope(ts, victim_switch, WARNING, block("REP", WARNING, "LINKSTATUS", body))
        roll = rng.random()
        if roll < 0.7:
            ip = rng.choice(victim_plcs)
            body = f"Lost communication with PLC at {ip} over {victim_proto}"
            return envelope(ts, victim_switch, ERR, block("IND", ERR, "PLC_COMM_LOSS", body))
        if roll < 0.85:
            body = f"Port {victim_port} changed state to DOWN"
            return envelope(
                ts, victim_switch, NOTICE, block("PORT", NOTICE, "LINK_STATE_CHANGE", body)
            )
        body = f"Segment {victim_segment} port {victim_port} link status FAILED"
        return envelope(ts, victim_switch, WARNING, block("REP", WARNING, "LINKSTATUS", body))

    def make_event(ts: datetime, seq: int) -> str | None:
        if (
            burst is not None
            and burst.active(ts)
            and rng.random() < 0.65 + 0.3 * burst.intensity(ts)
        ):
            return incident_event(ts)
        cisco_fac, severity, mnemonic, body_fn = pick(rng, msg_types, msg_weights)
        host = pick(rng, devices, device_weights)
        return envelope(ts, host, severity, block(cisco_fac, severity, mnemonic, body_fn()))

    return make_event


def main(argv: list[str] | None = None) -> int:
    parser = base_parser(
        "logsim-ics",
        "Generate realistic OT / ICS network-device syslog (Cisco-IOS-style "
        "%FAC-SEV-MNEMONIC events) from a Purdue-model plant floor.",
        default_rate=10.0,
    )
    parser.add_argument(
        "--rfc",
        choices=["5424", "3164"],
        default="5424",
        help="syslog wire format: RFC 5424 (default) or classic BSD RFC 3164",
    )
    parser.add_argument(
        "--scenario",
        choices=["none", "plc-comm-loss"],
        default="none",
        help="inject recurring OT-incident anomaly windows (default: none)",
    )
    args = parser.parse_args(argv)
    cfg = config_from_args(args)
    run(cfg, build_event_fn(cfg, args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
