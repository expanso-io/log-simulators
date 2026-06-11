"""Cisco ASA firewall syslog simulator.

Stateful connection lifecycle: an open-connection table pairs every
Teardown (302014/302016) with a previously Built (302013/302015)
connection id, computing the duration from the virtual clock and drawing
byte counts from a lognormal. Connection ids increase monotonically from
a seeded start; the table is capped, force-tearing-down the oldest
connection (Idle Timeout) when full.

Message mix per slot: ~40% build, ~35% teardown, ~15% ACL deny (106023),
~8.5% dynamic NAT translation (305011), <2% management garnish
(605005 SSH login / 113019 VPN session disconnect).

Format (one line per event, %ASA-<sev>-<id>: ...):
  %ASA-6-302013: Built outbound TCP connection 506986 for
      outside:203.0.113.30/443 (203.0.113.30/443) to
      inside:192.168.1.44/61094 (198.51.100.7/61094)
  %ASA-6-302014: Teardown TCP connection 506986 for ... duration 0:02:11
      bytes 4312 TCP FINs
  %ASA-4-106023: Deny tcp src outside:203.0.113.99/55842 dst
      inside:10.0.1.50/3389 by access-group "OUTSIDE_IN" [0x0, 0x0]

Flags:
  --syslog-header  prefix '<PRI>Mmm dd HH:MM:SS host : ' (facility
                   local4, severity taken from the message tag)

Scenarios:
  port-scan  recurring windows where one outside IP sweeps sequential
             destination ports on one inside host (106023 deny flood)
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
    internal_ips,
    lognormal_int,
    make_faker,
    pick,
    pri,
    public_ips,
    rfc3164_ts,
    run,
    usernames,
    zipf_weights,
)

HOSTNAME = "fw-edge-01"
SYSLOG_FACILITY = 20  # local4, the ASA default
MAX_OPEN_CONNS = 400

TCP_PORTS = [443, 80, 22, 8443, 25, 993, 5432]
TCP_PORT_WEIGHTS = [55.0, 20.0, 8.0, 6.0, 4.0, 4.0, 3.0]
UDP_PORTS = [53, 123, 500, 4500, 161]
UDP_PORT_WEIGHTS = [70.0, 12.0, 8.0, 5.0, 5.0]
DENY_PORTS = [3389, 23, 445, 1433, 22, 8080, 5900, 135]
DENY_PORT_WEIGHTS = [30.0, 14.0, 12.0, 10.0, 10.0, 9.0, 8.0, 7.0]

TEARDOWN_REASONS = ["TCP FINs", "TCP Reset-I", "TCP Reset-O", "SYN Timeout", "Idle Timeout"]
TEARDOWN_REASON_WEIGHTS = [55.0, 14.0, 11.0, 8.0, 12.0]

ADMIN_USERS = ["admin", "secops", "netops"]
VPN_DISCONNECT_REASONS = ["User Requested", "Idle Timeout", "Max time exceeded"]


@dataclass
class ConnState:
    proto: str  # "TCP" | "UDP"
    out_ip: str
    out_port: int
    in_ip: str
    in_port: int
    nat_ip: str
    built_at: datetime


def _duration(seconds: int) -> str:
    h, rem = divmod(max(0, seconds), 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}"


def build_event_fn(cfg: RunConfig, args: argparse.Namespace) -> EventFn:
    rng = cfg.content_rng()
    fk = make_faker(cfg.seed)
    inside = internal_ips(rng, 24, prefix="10.0") + [
        f"192.168.1.{octet}" for octet in rng.sample(range(2, 250), 12)
    ]
    inside_weights = zipf_weights(len(inside), s=0.9)
    outside = public_ips(fk, 120)
    outside_weights = zipf_weights(len(outside), s=0.8)
    nat_pool = public_ips(fk, 4)
    nat_map = {ip: nat_pool[rng.randrange(len(nat_pool))] for ip in inside}
    mgmt_hosts = rng.sample(inside, 3)
    vpn_users = usernames(fk, 10)

    scan = BurstSchedule(period=600, length=45) if args.scenario == "port-scan" else None
    scanner_ip = fk.ipv4_public()
    scan_target = rng.choice(inside)
    scan_dst_port = rng.randint(1, 100)
    scan_src_port = rng.randint(40000, 50000)

    next_conn_id = rng.randint(100_000, 800_000)
    open_conns: dict[int, ConnState] = {}

    def build_line(ts: datetime) -> str:
        nonlocal next_conn_id
        tcp = rng.random() < 0.75
        proto = "TCP" if tcp else "UDP"
        out_port = (
            pick(rng, TCP_PORTS, TCP_PORT_WEIGHTS)
            if tcp
            else pick(rng, UDP_PORTS, UDP_PORT_WEIGHTS)
        )
        in_ip = pick(rng, inside, inside_weights)
        conn = ConnState(
            proto=proto,
            out_ip=pick(rng, outside, outside_weights),
            out_port=out_port,
            in_ip=in_ip,
            in_port=rng.randint(32768, 65535),
            nat_ip=nat_map[in_ip],
            built_at=ts,
        )
        cid = next_conn_id
        next_conn_id += 1
        open_conns[cid] = conn
        code = "302013" if tcp else "302015"
        return (
            f"%ASA-6-{code}: Built outbound {proto} connection {cid} for "
            f"outside:{conn.out_ip}/{conn.out_port} ({conn.out_ip}/{conn.out_port}) to "
            f"inside:{conn.in_ip}/{conn.in_port} ({conn.nat_ip}/{conn.in_port})"
        )

    def teardown_line(ts: datetime, cid: int, forced: bool = False) -> str:
        conn = open_conns.pop(cid)
        dur = _duration(int((ts - conn.built_at).total_seconds()))
        base = (
            f"for outside:{conn.out_ip}/{conn.out_port} to "
            f"inside:{conn.in_ip}/{conn.in_port} duration {dur}"
        )
        if conn.proto == "UDP":
            nbytes = lognormal_int(rng, 380, 1.0, lo=60, hi=2_000_000)
            return f"%ASA-6-302016: Teardown UDP connection {cid} {base} bytes {nbytes}"
        nbytes = lognormal_int(rng, 5200, 1.3, lo=80, hi=80_000_000)
        reason = "Idle Timeout" if forced else pick(rng, TEARDOWN_REASONS, TEARDOWN_REASON_WEIGHTS)
        return f"%ASA-6-302014: Teardown TCP connection {cid} {base} bytes {nbytes} {reason}"

    def deny_line() -> str:
        proto = "tcp" if rng.random() < 0.85 else "udp"
        src = pick(rng, outside, outside_weights)
        dst = pick(rng, inside, inside_weights)
        return (
            f"%ASA-4-106023: Deny {proto} src outside:{src}/{rng.randint(1024, 65535)} "
            f"dst inside:{dst}/{pick(rng, DENY_PORTS, DENY_PORT_WEIGHTS)} "
            f'by access-group "OUTSIDE_IN" [0x0, 0x0]'
        )

    def scan_deny_line() -> str:
        nonlocal scan_dst_port, scan_src_port
        line = (
            f"%ASA-4-106023: Deny tcp src outside:{scanner_ip}/{scan_src_port} "
            f"dst inside:{scan_target}/{scan_dst_port} "
            f'by access-group "OUTSIDE_IN" [0x0, 0x0]'
        )
        scan_dst_port = scan_dst_port + 1 if scan_dst_port < 65535 else 1
        scan_src_port = scan_src_port + 1 if scan_src_port < 65535 else 40000
        return line

    def xlate_line() -> str:
        proto = "TCP" if rng.random() < 0.75 else "UDP"
        in_ip = pick(rng, inside, inside_weights)
        port = rng.randint(32768, 65535)
        return (
            f"%ASA-6-305011: Built dynamic {proto} translation from "
            f"inside:{in_ip}/{port} to outside:{nat_map[in_ip]}/{port}"
        )

    def mgmt_line() -> str:
        if rng.random() < 0.5:
            return (
                f"%ASA-6-605005: Login permitted from "
                f"{rng.choice(mgmt_hosts)}/{rng.randint(32768, 65535)} "
                f'to inside:10.0.0.1/ssh for user "{rng.choice(ADMIN_USERS)}"'
            )
        secs = lognormal_int(rng, 1800, 1.0, lo=30, hi=86400)
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        return (
            f"%ASA-4-113019: Group = REMOTE_VPN, Username = {rng.choice(vpn_users)}, "
            f"IP = {pick(rng, outside, outside_weights)}, Session disconnected. "
            f"Session Type: SSL, Duration: {h}h:{m:02d}m:{s:02d}s, "
            f"Bytes xmt: {lognormal_int(rng, 200_000, 1.4)}, "
            f"Bytes rcv: {lognormal_int(rng, 800_000, 1.4)}, "
            f"Reason: {rng.choice(VPN_DISCONNECT_REASONS)}"
        )

    def envelope(ts: datetime, line: str) -> str:
        if not args.syslog_header:
            return line
        severity = int(line[5])  # lines start '%ASA-<sev>-'
        return f"<{pri(SYSLOG_FACILITY, severity)}>{rfc3164_ts(ts)} {HOSTNAME} : {line}"

    def make_event(ts: datetime, seq: int) -> str:
        if scan is not None and scan.active(ts) and rng.random() < 0.45 + 0.5 * scan.intensity(ts):
            return envelope(ts, scan_deny_line())
        if len(open_conns) >= MAX_OPEN_CONNS:
            oldest = next(iter(open_conns))
            return envelope(ts, teardown_line(ts, oldest, forced=True))
        roll = rng.random()
        if roll < 0.75:
            if roll < 0.40 or not open_conns:
                return envelope(ts, build_line(ts))
            return envelope(ts, teardown_line(ts, rng.choice(list(open_conns))))
        if roll < 0.90:
            return envelope(ts, deny_line())
        if roll < 0.985:
            return envelope(ts, xlate_line())
        return envelope(ts, mgmt_line())

    return make_event


def main(argv: list[str] | None = None) -> int:
    parser = base_parser(
        "logsim-asa",
        "Generate realistic Cisco ASA firewall syslog with paired "
        "build/teardown connection events.",
        default_rate=10.0,
    )
    parser.add_argument(
        "--syslog-header",
        action="store_true",
        help="prefix each line with a syslog header '<PRI>Mmm dd HH:MM:SS host : '",
    )
    parser.add_argument(
        "--scenario",
        choices=["none", "port-scan"],
        default="none",
        help="inject recurring anomaly windows (default: none)",
    )
    args = parser.parse_args(argv)
    cfg = config_from_args(args)
    run(cfg, build_event_fn(cfg, args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
