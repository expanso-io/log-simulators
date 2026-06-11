#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["faker>=33.0.0"]
# ///
"""Single-file Apache access log generator (NCSA Combined Log Format).

Zero-install quick-taste version of `logsim-web` from
https://github.com/expanso-io/log-simulators - the packaged tool adds
sessions, nginx error logs, JSON output, scenarios, and network sinks.

    uv run web_access_sim.py --rate 10
    uv run web_access_sim.py --seed 42 --count 100
"""

from __future__ import annotations

import argparse
import contextlib
import random
import sys
import time
from datetime import datetime, timezone

from faker import Faker

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
PATHS = [
    "/",
    "/products",
    "/products/42",
    "/products/7",
    "/search?q=edge",
    "/cart",
    "/checkout",
    "/login",
    "/about",
    "/blog/launch",
    "/api/v1/products",
    "/static/css/main.css",
    "/static/js/app.js",
    "/favicon.ico",
]
PATH_WEIGHTS = [1.0 / (i + 1) ** 0.9 for i in range(len(PATHS))]
AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36",
    "curl/8.6.0",
]
REFERERS = ["-", "-", "-", "https://www.google.com/", "https://www.bing.com/"]
STATUSES = [200, 200, 200, 200, 200, 200, 200, 200, 304, 404, 301, 500]


def clf(ts: datetime) -> str:
    return f"{ts.day:02d}/{MONTHS[ts.month - 1]}/{ts.year}:{ts:%H:%M:%S} +0000"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rate", type=float, default=10.0, help="events/sec (default 10)")
    ap.add_argument("--count", type=int, default=0, help="stop after N lines (0 = forever)")
    ap.add_argument("--seed", type=int, default=None, help="reproducible output")
    args = ap.parse_args()
    if args.rate <= 0:
        ap.error("--rate must be > 0")

    rng = random.Random(args.seed)
    fk = Faker()
    if args.seed is not None:
        fk.seed_instance(args.seed)
    ips = [fk.ipv4_public() for _ in range(50)]
    users = [fk.user_name() for _ in range(20)] + ["-"] * 40

    emitted = 0
    try:
        while not args.count or emitted < args.count:
            ts = datetime.now(timezone.utc)
            path = rng.choices(PATHS, weights=PATH_WEIGHTS, k=1)[0]
            method = "POST" if path in ("/login", "/checkout") else "GET"
            status = rng.choice(STATUSES)
            nbytes = 0 if status == 304 else rng.randint(200, 50_000)
            print(
                f"{rng.choice(ips)} - {rng.choice(users)} [{clf(ts)}] "
                f'"{method} {path} HTTP/1.1" {status} {nbytes} '
                f'"{rng.choice(REFERERS)}" "{rng.choice(AGENTS)}"',
                flush=True,
            )
            emitted += 1
            time.sleep(rng.expovariate(args.rate))
    except (KeyboardInterrupt, BrokenPipeError):
        with contextlib.suppress(Exception):
            sys.stdout.close()
    print(f"[web_access_sim] emitted {emitted} lines", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
