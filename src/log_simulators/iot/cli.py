"""IoT sensor telemetry simulator (environmental monitoring fleet).

Models a fleet of environmental sensors with stable identities - the same
device id always reports the same model, firmware, city, and GPS-fuzzed
coordinates. Readings are gaussian per metric with a slow per-device
random-walk drift plus a diurnal temperature curve (peak mid-afternoon).
Lineage: bacalhau-project/sensor-log-generator, rebuilt on the shared core.

Formats:
  ndjson  one JSON reading per line (default)
  csv     header row once, then one comma-separated reading per row

Anomalies (~2% baseline, weighted): spike (2-3 std excursion), stuck
(sensor repeats its last value exactly for a few readings), dropout
(reading lost - the slot is skipped, nothing is emitted), and noise
(10-15% multiplicative). Anomalous readings carry anomaly_flag=true,
anomaly_type, and status_code=1.

Scenarios:
  sensor-fault  recurring windows where ONE device's anomaly probability
                jumps to ~60% (spike-heavy with thermal/vibration drift) -
                a failing unit, the classic edge-filtering demo
"""

from __future__ import annotations

import argparse
import json
import math
import random
from dataclasses import dataclass, field
from datetime import datetime

from log_simulators.core import (
    BurstSchedule,
    EventFn,
    RunConfig,
    base_parser,
    clamp,
    config_from_args,
    iso_ms,
    run,
)

# (id prefix, city, latitude, longitude)
CITIES = [
    ("CHIC", "Chicago", 41.8781, -87.6298),
    ("SEAT", "Seattle", 47.6062, -122.3321),
    ("AUST", "Austin", 30.2672, -97.7431),
    ("DENV", "Denver", 39.7392, -104.9903),
    ("ATLA", "Atlanta", 33.7490, -84.3880),
    ("PORT", "Portland", 45.5152, -122.6784),
    ("BOST", "Boston", 42.3601, -71.0589),
    ("PHOE", "Phoenix", 33.4484, -112.0740),
]
MANUFACTURERS = ["SensorTech", "EnvSystems", "IoTPro"]
MODELS = ["EnvMonitor-3000", "EnvMonitor-4000", "AirSense-Pro"]
FIRMWARE_VERSIONS = ["1.3.2", "1.4.0", "1.4.1", "1.5.0"]
# 1.4.x is the flaky release line, 1.5.x the stabilized one (lineage behavior)
FIRMWARE_ANOMALY_FACTOR = {"1.3": 1.0, "1.4": 1.5, "1.5": 0.7}
ID_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

# metric -> (mean, std, physical min, physical max, output decimals)
METRICS: dict[str, tuple[float, float, float, float, int]] = {
    "temperature": (22.0, 1.5, -20.0, 60.0, 2),  # Celsius
    "humidity": (60.0, 8.0, 0.0, 100.0, 1),  # percent RH
    "pressure": (1013.0, 4.0, 950.0, 1050.0, 1),  # hPa
    "vibration": (2.5, 0.8, 0.0, 50.0, 1),  # mm/s
    "voltage": (12.0, 0.3, 0.0, 24.0, 2),  # V
}
SPIKE_METRICS = ["temperature", "humidity", "voltage", "vibration"]

FIELDS = [
    "timestamp",
    "sensor_id",
    "temperature",
    "humidity",
    "pressure",
    "vibration",
    "voltage",
    "status_code",
    "anomaly_flag",
    "anomaly_type",
    "firmware_version",
    "model",
    "manufacturer",
    "location",
    "latitude",
    "longitude",
]

BASE_ANOMALY_P = 0.02
FAULT_ANOMALY_P = 0.60
BASELINE_ANOMALIES = (["spike", "stuck", "dropout", "noise"], [0.40, 0.25, 0.15, 0.20])
FAULT_ANOMALIES = (["spike", "drift", "noise", "stuck"], [0.55, 0.25, 0.15, 0.05])
DIURNAL_TEMP_AMPLITUDE = 2.5  # deg C swing across the day, peak ~15:00 local


@dataclass
class Device:
    sensor_id: str
    location: str
    latitude: float
    longitude: float
    manufacturer: str
    model: str
    firmware: str
    anomaly_factor: float
    drift: dict[str, float] = field(default_factory=dict)
    last: dict[str, float] | None = None
    stuck_remaining: int = 0
    stuck_values: dict[str, float] | None = None


def _build_fleet(rng: random.Random, n: int) -> list[Device]:
    devices: list[Device] = []
    used: set[str] = set()
    for _ in range(n):
        code, city, lat, lon = rng.choice(CITIES)
        while True:
            sensor_id = f"{code}-{''.join(rng.choice(ID_ALPHABET) for _ in range(6))}"
            if sensor_id not in used:
                break
        used.add(sensor_id)
        firmware = rng.choice(FIRMWARE_VERSIONS)
        devices.append(
            Device(
                sensor_id=sensor_id,
                location=city,
                latitude=round(lat + rng.uniform(-0.02, 0.02), 4),
                longitude=round(lon + rng.uniform(-0.02, 0.02), 4),
                manufacturer=rng.choice(MANUFACTURERS),
                model=rng.choice(MODELS),
                firmware=firmware,
                anomaly_factor=FIRMWARE_ANOMALY_FACTOR[firmware.rsplit(".", 1)[0]],
            )
        )
    return devices


def _sample_metric(rng: random.Random, device: Device, metric: str, ts: datetime) -> float:
    """Gaussian baseline + slow per-device random-walk drift, clamped to physics."""
    mean, std, lo, hi, _ = METRICS[metric]
    walk = clamp(device.drift.get(metric, 0.0) + rng.gauss(0.0, std * 0.02), -0.5 * std, 0.5 * std)
    device.drift[metric] = walk
    value = rng.gauss(mean, std) + walk
    if metric == "temperature":
        hour = ts.hour + ts.minute / 60.0
        value += DIURNAL_TEMP_AMPLITUDE * math.sin(2.0 * math.pi * (hour - 9.0) / 24.0)
    return clamp(value, lo, hi)


def _apply_spike(rng: random.Random, metrics: dict[str, float]) -> None:
    """2-3 std excursion from the mean on one metric, either direction."""
    metric = rng.choice(SPIKE_METRICS)
    mean, std, lo, hi, _ = METRICS[metric]
    sign = 1.0 if rng.random() < 0.5 else -1.0
    metrics[metric] = clamp(mean + sign * rng.uniform(2.0, 3.0) * std, lo, hi)


def _apply_noise(rng: random.Random, metrics: dict[str, float]) -> None:
    """10-15% multiplicative noise on every metric."""
    for metric in metrics:
        _, _, lo, hi, _ = METRICS[metric]
        sign = 1.0 if rng.random() < 0.5 else -1.0
        metrics[metric] = clamp(metrics[metric] * (1.0 + sign * rng.uniform(0.10, 0.15)), lo, hi)


def _apply_drift(rng: random.Random, metrics: dict[str, float], intensity: float) -> None:
    """Failing-unit runaway: temperature and vibration climb with burst intensity."""
    for metric in ("temperature", "vibration"):
        _, std, lo, hi, _ = METRICS[metric]
        metrics[metric] = clamp(
            metrics[metric] + rng.uniform(1.0, 2.0) * std * (0.5 + intensity), lo, hi
        )


def _record(
    ts: datetime, device: Device, metrics: dict[str, float], anomaly_type: str | None
) -> dict[str, object]:
    rec: dict[str, object] = {"timestamp": iso_ms(ts), "sensor_id": device.sensor_id}
    for metric, (_, _, _, _, decimals) in METRICS.items():
        rec[metric] = round(metrics[metric], decimals)
    rec.update(
        {
            "status_code": 1 if anomaly_type else 0,
            "anomaly_flag": anomaly_type is not None,
            "anomaly_type": anomaly_type,
            "firmware_version": device.firmware,
            "model": device.model,
            "manufacturer": device.manufacturer,
            "location": device.location,
            "latitude": device.latitude,
            "longitude": device.longitude,
        }
    )
    return rec


def _csv_row(rec: dict[str, object]) -> str:
    parts: list[str] = []
    for name in FIELDS:
        value = rec[name]
        if value is None:
            parts.append("")
        elif isinstance(value, bool):
            parts.append("true" if value else "false")
        else:
            parts.append(str(value))
    return ",".join(parts)


def build_event_fn(cfg: RunConfig, args: argparse.Namespace) -> EventFn:
    rng = cfg.content_rng()
    devices = _build_fleet(rng, args.devices)
    fault = BurstSchedule(period=600, length=60) if args.scenario == "sensor-fault" else None
    fault_device = devices[cfg.content_rng("fault").randrange(len(devices))] if fault else None
    header_pending = args.format == "csv"

    def render(ts: datetime, device: Device, metrics: dict[str, float], atype: str | None) -> str:
        nonlocal header_pending
        rec = _record(ts, device, metrics, atype)
        if args.format == "csv":
            row = _csv_row(rec)
            if header_pending:
                header_pending = False
                return ",".join(FIELDS) + "\n" + row
            return row
        return json.dumps(rec, separators=(",", ":"))

    def make_event(ts: datetime, seq: int) -> str | None:
        device = devices[rng.randrange(len(devices))]
        if device.stuck_remaining > 0 and device.stuck_values is not None:
            device.stuck_remaining -= 1
            return render(ts, device, dict(device.stuck_values), "stuck")

        metrics = {metric: _sample_metric(rng, device, metric, ts) for metric in METRICS}
        in_fault = fault is not None and device is fault_device and fault.active(ts)
        probability = FAULT_ANOMALY_P if in_fault else BASE_ANOMALY_P * device.anomaly_factor

        anomaly_type: str | None = None
        if rng.random() < probability:
            kinds, weights = FAULT_ANOMALIES if in_fault else BASELINE_ANOMALIES
            anomaly_type = rng.choices(kinds, weights=weights, k=1)[0]
            if anomaly_type == "dropout":
                return None  # reading lost; the engine counts a skipped slot
            if anomaly_type == "stuck":
                device.stuck_values = dict(device.last) if device.last else dict(metrics)
                device.stuck_remaining = rng.randint(1, 4)
                metrics = dict(device.stuck_values)
            elif anomaly_type == "spike":
                _apply_spike(rng, metrics)
            elif anomaly_type == "noise":
                _apply_noise(rng, metrics)
            elif anomaly_type == "drift" and fault is not None:
                _apply_drift(rng, metrics, fault.intensity(ts))

        device.last = dict(metrics)
        return render(ts, device, metrics, anomaly_type)

    return make_event


def main(argv: list[str] | None = None) -> int:
    parser = base_parser(
        "logsim-iot",
        "Generate realistic IoT environmental sensor telemetry from a device fleet.",
        default_rate=10.0,
    )
    parser.add_argument(
        "--format",
        choices=["ndjson", "csv"],
        default="ndjson",
        help="output format (default: ndjson)",
    )
    parser.add_argument(
        "--devices",
        type=int,
        default=5,
        metavar="N",
        help="number of sensor devices in the fleet (default: 5)",
    )
    parser.add_argument(
        "--scenario",
        choices=["none", "sensor-fault"],
        default="none",
        help="inject recurring anomaly windows on one failing device (default: none)",
    )
    args = parser.parse_args(argv)
    if args.devices < 1:
        parser.error("--devices must be >= 1")
    cfg = config_from_args(args)
    run(cfg, build_event_fn(cfg, args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
