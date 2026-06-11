"""CEF / LEEF security event simulator (firewall / IPS / EDR style).

Models a fictional Expanso "EdgeGuard" edge security appliance. The same
internal hosts, public destinations, and usernames recur coherently, and
the severity mix is deliberately info-heavy with rare high-severity
detections - the classic "filter sev>=7 at the edge" demo.

Formats:
  cef   ArcSight CEF (default):
        CEF:0|Expanso|EdgeGuard|2.4.1|{sigId}|{name}|{severity}|{extensions}
        Header fields escape backslash and '|'. Extensions are
        space-separated key=value pairs; backslash, '=' and newlines in
        values are escaped per the CEF spec - pipes pass through
        unescaped in extension values. --syslog-header prefixes each
        event with 'Jun 10 22:14:15 edge-01 '.
  leef  IBM QRadar LEEF 2.0:
        LEEF:2.0|Expanso|EdgeGuard|2.4.1|{eventId}| followed by
        TAB-separated key=value attributes (devTime, src, dst, srcPort,
        dstPort, proto, usrName, action, sev, ...).

Scenarios:
  malware-burst  recurring windows where a single infected internal host
                 emits a wave of sev>=9 Malware/C2 events sharing a small
                 set of file hashes
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime

from log_simulators.core import (
    BurstSchedule,
    EventFn,
    RunConfig,
    base_parser,
    clamp,
    config_from_args,
    hostnames,
    internal_ips,
    make_faker,
    pick,
    public_ips,
    rfc3164_ts,
    run,
    usernames,
    zipf_weights,
)

VENDOR = "Expanso"
PRODUCT = "EdgeGuard"
VERSION = "2.4.1"

# (signature id, event name, severity lo, severity hi, relative weight)
CATALOG: list[tuple[str, str, int, int, float]] = [
    ("100", "Connection allowed", 1, 3, 70.0),
    ("101", "Connection blocked by policy", 4, 6, 15.0),
    ("200", "Port scan detected", 7, 7, 3.0),
    ("300", "Malware blocked", 9, 10, 1.5),
    ("301", "C2 callback blocked", 9, 9, 0.5),
    ("400", "Failed authentication", 5, 5, 8.0),
    ("401", "Brute force detected", 8, 8, 2.0),
]
CATALOG_WEIGHTS = [entry[4] for entry in CATALOG]
BY_ID = {entry[0]: entry for entry in CATALOG}

# (application, destination port, protocol) - HTTPS-heavy like real egress
APPS: list[tuple[str, int, str]] = [
    ("HTTPS", 443, "TCP"),
    ("HTTP", 80, "TCP"),
    ("DNS", 53, "UDP"),
    ("SSH", 22, "TCP"),
    ("SMTP", 25, "TCP"),
    ("RDP", 3389, "TCP"),
    ("SMB", 445, "TCP"),
    ("LDAP", 389, "TCP"),
]
APP_WEIGHTS = [40.0, 18.0, 16.0, 8.0, 6.0, 5.0, 4.0, 3.0]
AUTH_APPS = ["SSH", "RDP", "LDAP"]
AUTH_PORTS = {"SSH": 22, "RDP": 3389, "LDAP": 389}

ALLOW_RULES = ["Allow-Outbound-Web", "Allow-DNS-Resolvers", "Allow-Corp-VPN", "Allow-SaaS-Sync"]
BLOCK_RULES = ["Block-Inbound-Default", "Geo-Block-Embargo", "Threat-Intel-Feed", "Deny-P2P"]

ALLOW_MSGS = [
    "Session permitted by policy",
    "Stateful match on existing flow",
    "TLS session established",
]
# Two of these contain literal pipes on purpose: per the CEF spec pipes are
# escaped only in header fields, so they must pass through extensions as-is.
BLOCK_MSGS = [
    "Denied by policy chain edge|perimeter",
    "Matched deny rule on zone pair lan|wan",
    "Outbound connection rejected at enforcement point",
    "Connection dropped: destination on blocklist",
]

# Windows paths exercise backslash escaping in CEF extension values.
MALWARE_FILES = [
    "C:\\Users\\{user}\\Downloads\\invoice_2026.pdf.exe",
    "C:\\Users\\{user}\\AppData\\Local\\Temp\\update_helper.exe",
    "C:\\ProgramData\\svch0st.exe",
    "/tmp/.cache/xmrig",
]
C2_DOMAINS = ["cdn-sync-update.net", "telemetry-node7.xyz", "static-assets-cache.top"]


def header_escape(value: str) -> str:
    """Escape backslash and '|' in CEF header fields (backslash first)."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def ext_escape(value: str) -> str:
    """Escape backslash, '=' and newlines in CEF extension values (backslash first).

    Pipes are intentionally NOT escaped here: per the ArcSight CEF spec they
    are only escaped in header fields.
    """
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r")


def _sha256(rng: random.Random) -> str:
    return "".join(rng.choices("0123456789abcdef", k=64))


def build_event_fn(cfg: RunConfig, args: argparse.Namespace) -> EventFn:
    rng = cfg.content_rng()
    fk = make_faker(cfg.seed)
    src_pool = internal_ips(rng, 40)
    src_weights = zipf_weights(len(src_pool), s=0.8)
    attacker_pool = public_ips(fk, 12)
    dst_pool = public_ips(fk, 60)
    dst_weights = zipf_weights(len(dst_pool), s=0.9)
    users = usernames(fk, 30)
    user_weights = zipf_weights(len(users))
    reporters = hostnames(rng, 8, prefix="edge")
    server_pool = internal_ips(rng, 6, prefix="10.1")
    dhost_pool = sorted({fk.domain_name() for _ in range(40)})

    burst = BurstSchedule(period=600, length=60) if args.scenario == "malware-burst" else None
    infected_src = pick(rng, src_pool)
    burst_hashes = [_sha256(rng) for _ in range(3)]
    burst_files = rng.sample(MALWARE_FILES, k=2)
    burst_user = pick(rng, users, user_weights)
    burst_c2 = rng.choice(C2_DOMAINS)

    def fields_for(ts: datetime) -> dict[str, str]:
        burst_hit = (
            burst is not None
            and burst.active(ts)
            and rng.random() < 0.5 + 0.45 * burst.intensity(ts)
        )
        if burst_hit:
            sig_id = "300" if rng.random() < 0.65 else "301"
        else:
            sig_id = pick(rng, CATALOG, CATALOG_WEIGHTS)[0]
        _, name, lo, hi, _w = BY_ID[sig_id]
        sev = rng.randint(lo, hi)
        app, dpt, proto = pick(rng, APPS, APP_WEIGHTS)
        f: dict[str, str] = {
            "sig_id": sig_id,
            "name": name,
            "sev": str(sev),
            "host": rng.choice(reporters),
            "src": pick(rng, src_pool, src_weights),
            "dst": pick(rng, dst_pool, dst_weights),
            "spt": str(rng.randint(1024, 65535)),
            "dpt": str(dpt),
            "proto": proto,
            "app": app,
            "act": "blocked",
            "score": str(int(clamp(sev * 10 + rng.randint(-8, 8), 1, 100))),
        }
        if sig_id == "100":
            f["act"] = "allowed"
            f["rule"] = rng.choice(ALLOW_RULES)
            f["msg"] = rng.choice(ALLOW_MSGS)
            if rng.random() < 0.35:
                f["suser"] = pick(rng, users, user_weights)
            if rng.random() < 0.4:
                f["dhost"] = rng.choice(dhost_pool)
        elif sig_id == "101":
            f["rule"] = rng.choice(BLOCK_RULES)
            f["msg"] = rng.choice(BLOCK_MSGS)
            if rng.random() < 0.3:
                f["dhost"] = rng.choice(dhost_pool)
        elif sig_id == "200":
            f["src"] = rng.choice(attacker_pool)
            f["dst"] = rng.choice(server_pool)
            f["rule"] = "IPS-PortScan"
            f["msg"] = f"{rng.randint(40, 900)} ports probed within 10s window"
        elif sig_id == "300":
            user = burst_user if burst_hit else pick(rng, users, user_weights)
            if burst_hit:
                f["src"] = infected_src
                f["fileHash"] = rng.choice(burst_hashes)
                file_name = rng.choice(burst_files)
            else:
                f["fileHash"] = _sha256(rng)
                file_name = rng.choice(MALWARE_FILES)
            f["suser"] = user
            f["fileName"] = file_name.format(user=user)
            f["rule"] = "EDR-Realtime"
            f["msg"] = "Malicious file quarantined by EdgeGuard AV"
        elif sig_id == "301":
            if burst_hit:
                f["src"] = infected_src
                f["dhost"] = burst_c2
            else:
                f["dhost"] = rng.choice(C2_DOMAINS)
            f["app"] = "HTTPS"
            f["dpt"] = "443"
            f["proto"] = "TCP"
            f["rule"] = "Threat-Intel-Feed"
            f["msg"] = "Beacon to known C2 infrastructure blocked"
        else:  # 400 / 401 authentication events
            auth_app = rng.choice(AUTH_APPS)
            f["app"] = auth_app
            f["dpt"] = str(AUTH_PORTS[auth_app])
            f["proto"] = "TCP"
            f["dst"] = rng.choice(server_pool)
            f["suser"] = pick(rng, users, user_weights)
            f["rule"] = "Auth-Policy"
            if sig_id == "400":
                f["msg"] = f"Invalid credentials for user via {auth_app}"
            else:
                f["msg"] = f"{rng.randint(8, 60)} failed logins within 60s"
        return f

    def cef_line(ts: datetime, f: dict[str, str]) -> str:
        pairs: list[tuple[str, str]] = [
            ("src", f["src"]),
            ("spt", f["spt"]),
            ("dst", f["dst"]),
            ("dpt", f["dpt"]),
            ("proto", f["proto"]),
            ("act", f["act"]),
            ("app", f["app"]),
            ("cs1Label", "Rule"),
            ("cs1", f["rule"]),
            ("cn1Label", "ThreatScore"),
            ("cn1", f["score"]),
        ]
        for key in ("suser", "dhost", "fileHash", "fileName"):
            if key in f:
                pairs.append((key, f[key]))
        pairs.append(("msg", f["msg"]))
        ext = " ".join(f"{k}={ext_escape(v)}" for k, v in pairs)
        head = (VENDOR, PRODUCT, VERSION, f["sig_id"], f["name"], f["sev"])
        header = "|".join(["CEF:0", *(header_escape(part) for part in head)])
        line = f"{header}|{ext}"
        if args.syslog_header:
            return f"{rfc3164_ts(ts)} {f['host']} {line}"
        return line

    def leef_line(ts: datetime, f: dict[str, str]) -> str:
        attrs: list[tuple[str, str]] = [
            ("devTime", ts.strftime("%b %d %Y %H:%M:%S")),
            ("src", f["src"]),
            ("dst", f["dst"]),
            ("srcPort", f["spt"]),
            ("dstPort", f["dpt"]),
            ("proto", f["proto"]),
            ("usrName", f.get("suser", "-")),
            ("action", f["act"]),
            ("sev", f["sev"]),
            ("cat", f["name"]),
            ("msg", f["msg"]),
        ]
        body = "\t".join(f"{k}={v}" for k, v in attrs)
        line = f"LEEF:2.0|{VENDOR}|{PRODUCT}|{VERSION}|{f['sig_id']}|{body}"
        if args.syslog_header:
            return f"{rfc3164_ts(ts)} {f['host']} {line}"
        return line

    def make_event(ts: datetime, seq: int) -> str:
        f = fields_for(ts)
        if args.format == "leef":
            return leef_line(ts, f)
        return cef_line(ts, f)

    return make_event


def main(argv: list[str] | None = None) -> int:
    parser = base_parser(
        "logsim-cef",
        "Generate CEF/LEEF security events from a simulated edge firewall/IPS/EDR.",
        default_rate=10.0,
    )
    parser.add_argument(
        "--format",
        choices=["cef", "leef"],
        default="cef",
        help="output format (default: cef)",
    )
    parser.add_argument(
        "--scenario",
        choices=["none", "malware-burst"],
        default="none",
        help="inject recurring anomaly windows (default: none)",
    )
    parser.add_argument(
        "--syslog-header",
        action="store_true",
        help="prefix each event with a BSD syslog header ('Jun 10 22:14:15 edge-01 ')",
    )
    args = parser.parse_args(argv)
    cfg = config_from_args(args)
    run(cfg, build_event_fn(cfg, args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
