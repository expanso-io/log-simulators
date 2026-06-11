#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Single-file syslog generator (RFC 3164 or RFC 5424).

Zero-install quick-taste version of `logsim-syslog` from
https://github.com/expanso-io/log-simulators - the packaged tool adds richer
program/message catalogs, auth-burst scenarios, and TCP/UDP network sinks.

    uv run syslog_sim.py --rate 10
    uv run syslog_sim.py --rfc 3164 --seed 42 --count 100
"""

from __future__ import annotations

import argparse
import contextlib
import random
import sys
import time
from datetime import datetime, timezone

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
HOSTS = [f"edge-gw-{i:02d}" for i in range(1, 5)] + [f"app-{i:02d}" for i in range(1, 4)]
# (program, facility, [(severity, message template), ...])
CATALOG = [
    (
        "sshd",
        4,
        [
            (6, "Accepted publickey for deploy from 10.0.{o}.{h} port {p} ssh2"),
            (4, "Failed password for invalid user admin from 203.0.113.{h} port {p} ssh2"),
            (6, "pam_unix(sshd:session): session opened for user deploy"),
        ],
    ),
    (
        "CRON",
        9,
        [
            (6, "(root) CMD (/usr/local/bin/backup.sh)"),
            (6, "(www-data) CMD (php /var/www/cron.php)"),
        ],
    ),
    (
        "systemd",
        3,
        [
            (6, "Started Daily apt download activities."),
            (6, "Reloading nginx configuration..."),
            (4, "app.service: Watchdog timeout!"),
        ],
    ),
    (
        "kernel",
        0,
        [
            (6, "eth0: link up, 1000Mbps, full-duplex"),
            (3, "Out of memory: Killed process {p} (java)"),
        ],
    ),
    (
        "postfix/smtpd",
        2,
        [
            (6, "connect from mail.example.com[198.51.100.{h}]"),
            (5, "NOQUEUE: reject: RCPT from unknown[203.0.113.{h}]"),
        ],
    ),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rate", type=float, default=10.0, help="events/sec (default 10)")
    ap.add_argument("--count", type=int, default=0, help="stop after N lines (0 = forever)")
    ap.add_argument("--seed", type=int, default=None, help="reproducible output")
    ap.add_argument("--rfc", choices=["3164", "5424"], default="5424", help="syslog flavor")
    args = ap.parse_args()
    if args.rate <= 0:
        ap.error("--rate must be > 0")

    rng = random.Random(args.seed)
    emitted = 0
    try:
        while not args.count or emitted < args.count:
            ts = datetime.now(timezone.utc)
            host = rng.choice(HOSTS)
            prog, facility, messages = rng.choice(CATALOG)
            severity, template = rng.choices(
                messages, weights=[3 if s >= 6 else 1 for s, _ in messages], k=1
            )[0]
            msg = template.format(
                o=rng.randint(1, 9), h=rng.randint(2, 254), p=rng.randint(1024, 65000)
            )
            pid = rng.randint(300, 30000)
            pri = facility * 8 + severity
            if args.rfc == "3164":
                stamp = f"{MONTHS[ts.month - 1]} {ts.day:2d} {ts:%H:%M:%S}"
                line = f"<{pri}>{stamp} {host} {prog}[{pid}]: {msg}"
            else:
                stamp = f"{ts:%Y-%m-%dT%H:%M:%S}.{ts.microsecond // 1000:03d}Z"
                line = f"<{pri}>1 {stamp} {host} {prog} {pid} - - {msg}"
            print(line, flush=True)
            emitted += 1
            time.sleep(rng.expovariate(args.rate))
    except (KeyboardInterrupt, BrokenPipeError):
        with contextlib.suppress(Exception):
            sys.stdout.close()
    print(f"[syslog_sim] emitted {emitted} lines", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
