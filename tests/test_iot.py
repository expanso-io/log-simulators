"""Tests for logsim-iot (IoT environmental sensor telemetry)."""

from __future__ import annotations

import json
import re
from collections import Counter

from log_simulators.iot.cli import main

from .conftest import generate

SENSOR_ID_RE = re.compile(r"^[A-Z]{4}-[A-HJ-NP-Z2-9]{6}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+00:00$")

REQUIRED_KEYS = {
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
}
ALLOWED_ANOMALY_TYPES = {"spike", "stuck", "noise", "drift"}
PHYSICAL_RANGES = {
    "temperature": (-20.0, 60.0),
    "humidity": (0.0, 100.0),
    "pressure": (950.0, 1050.0),
    "vibration": (0.0, 50.0),
    "voltage": (0.0, 24.0),
}
CSV_HEADER = (
    "timestamp,sensor_id,temperature,humidity,pressure,vibration,voltage,"
    "status_code,anomaly_flag,anomaly_type,firmware_version,model,manufacturer,"
    "location,latitude,longitude"
)


def _records(lines: list[str]) -> list[dict]:
    return [json.loads(line) for line in lines]


class TestFormats:
    def test_every_ndjson_line_parses_with_required_keys(self) -> None:
        for line in generate(main, count=300):
            record = json.loads(line)
            assert record.keys() >= REQUIRED_KEYS, line
            assert TIMESTAMP_RE.match(record["timestamp"]), line
            assert SENSOR_ID_RE.match(record["sensor_id"]), line
            assert record["status_code"] in (0, 1)
            assert isinstance(record["anomaly_flag"], bool)

    def test_csv_header_once_then_constant_column_count(self) -> None:
        lines = generate(main, count=200, extra=["--format", "csv"])
        assert lines[0] == CSV_HEADER
        assert lines.count(CSV_HEADER) == 1
        n_cols = len(CSV_HEADER.split(","))
        for row in lines[1:]:
            assert len(row.split(",")) == n_cols, row

    def test_values_within_physical_ranges(self) -> None:
        for record in _records(generate(main, count=1000)):
            for metric, (lo, hi) in PHYSICAL_RANGES.items():
                assert lo <= record[metric] <= hi, (metric, record[metric])
            assert 24.0 <= record["latitude"] <= 50.0
            assert -125.0 <= record["longitude"] <= -70.0


class TestDeterminism:
    def test_same_seed_same_output(self) -> None:
        assert generate(main, count=100) == generate(main, count=100)

    def test_different_seed_differs(self) -> None:
        assert generate(main, count=100, seed=1) != generate(main, count=100, seed=2)


class TestRealism:
    def test_device_identity_stable_across_readings(self) -> None:
        identity: dict[str, tuple] = {}
        for record in _records(generate(main, count=500)):
            key = record["sensor_id"]
            value = (
                record["model"],
                record["manufacturer"],
                record["firmware_version"],
                record["location"],
                record["latitude"],
                record["longitude"],
            )
            assert identity.setdefault(key, value) == value, key
        assert len(identity) == 5  # default fleet size, all devices report

    def test_devices_flag_controls_fleet_size(self) -> None:
        ids = {
            r["sensor_id"] for r in _records(generate(main, count=300, extra=["--devices", "3"]))
        }
        assert len(ids) == 3

    def test_anomaly_fields_consistent(self) -> None:
        for record in _records(generate(main, count=2000)):
            if record["anomaly_flag"]:
                assert record["status_code"] == 1
                assert record["anomaly_type"] in ALLOWED_ANOMALY_TYPES
            else:
                assert record["status_code"] == 0
                assert record["anomaly_type"] is None

    def test_dropouts_skip_slots_and_types_are_allowed(self) -> None:
        # 3000 slots requested; dropout anomalies consume slots without emitting,
        # so fewer lines than slots appear (deterministic with the fixed seed).
        lines = generate(main, count=3000)
        assert len(lines) < 3000
        observed = {r["anomaly_type"] for r in _records(lines) if r["anomaly_flag"]}
        assert observed  # baseline ~2% anomalies must show up at this volume
        assert observed <= ALLOWED_ANOMALY_TYPES  # dropout never appears in output

    def test_baseline_anomaly_rate_low(self) -> None:
        records = _records(generate(main, count=1000))
        rate = sum(r["anomaly_flag"] for r in records) / len(records)
        assert rate < 0.08


class TestScenario:
    def test_sensor_fault_raises_anomaly_rate(self) -> None:
        def anomaly_rate(extra: list[str]) -> float:
            records = _records(generate(main, count=800, backfill="2h", extra=extra))
            return sum(r["anomaly_flag"] for r in records) / len(records)

        baseline = anomaly_rate([])
        fault = anomaly_rate(["--scenario", "sensor-fault"])
        assert baseline < 0.06
        assert fault > baseline * 2

    def test_fault_concentrates_on_one_device(self) -> None:
        records = _records(
            generate(main, count=800, backfill="2h", extra=["--scenario", "sensor-fault"])
        )
        anomalous = [r["sensor_id"] for r in records if r["anomaly_flag"]]
        assert anomalous
        _top_id, top_count = Counter(anomalous).most_common(1)[0]
        assert top_count / len(anomalous) > 0.5  # one failing unit dominates
