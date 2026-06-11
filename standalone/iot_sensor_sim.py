#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Single-file IoT sensor telemetry generator (NDJSON).

Zero-install quick-taste version of `logsim-iot` from
https://github.com/expanso-io/log-simulators - the packaged tool adds a
device fleet, anomaly engine, fault scenarios, CSV output, and backfill.

    uv run iot_sensor_sim.py --rate 5
    uv run iot_sensor_sim.py --seed 42 --count 100
"""

from __future__ import annotations

import argparse
import contextlib
import json
import random
import sys
import time
from datetime import datetime, timezone

CITIES = [
    ("Chicago", 41.8781, -87.6298),
    ("Seattle", 47.6062, -122.3321),
    ("Austin", 30.2672, -97.7431),
    ("Denver", 39.7392, -104.9903),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rate", type=float, default=5.0, help="readings/sec (default 5)")
    ap.add_argument("--count", type=int, default=0, help="stop after N readings (0 = forever)")
    ap.add_argument("--seed", type=int, default=None, help="reproducible output")
    args = ap.parse_args()
    if args.rate <= 0:
        ap.error("--rate must be > 0")

    rng = random.Random(args.seed)
    devices = []
    for city, lat, lon in CITIES:
        suffix = "".join(rng.choices("ABCDEFGHJKMNPQRSTUVWXYZ23456789", k=6))
        devices.append(
            {
                "sensor_id": f"{city[:4].upper()}-{suffix}",
                "location": city,
                "latitude": round(lat + rng.uniform(-0.01, 0.01), 4),
                "longitude": round(lon + rng.uniform(-0.01, 0.01), 4),
                "temp": 22.0,
                "hum": 60.0,
                "press": 1013.0,
            }
        )

    emitted = 0
    try:
        while not args.count or emitted < args.count:
            d = rng.choice(devices)
            # small random walk + gaussian noise keeps values plausible
            d["temp"] += rng.gauss(0, 0.08)
            d["hum"] = min(100.0, max(0.0, d["hum"] + rng.gauss(0, 0.3)))
            d["press"] += rng.gauss(0, 0.15)
            anomaly = rng.random() < 0.02
            temp = d["temp"] + (rng.choice([-1, 1]) * rng.uniform(4, 8) if anomaly else 0)
            print(
                json.dumps(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                        "sensor_id": d["sensor_id"],
                        "temperature": round(temp + rng.gauss(0, 0.2), 2),
                        "humidity": round(d["hum"] + rng.gauss(0, 0.5), 1),
                        "pressure": round(d["press"] + rng.gauss(0, 0.3), 1),
                        "voltage": round(rng.gauss(12.0, 0.15), 2),
                        "anomaly_flag": anomaly,
                        "location": d["location"],
                        "latitude": d["latitude"],
                        "longitude": d["longitude"],
                    }
                ),
                flush=True,
            )
            emitted += 1
            time.sleep(rng.expovariate(args.rate))
    except (KeyboardInterrupt, BrokenPipeError):
        with contextlib.suppress(Exception):
            sys.stdout.close()
    print(f"[iot_sensor_sim] emitted {emitted} readings", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
