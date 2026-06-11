"""Tests for logsim-app (structured NDJSON microservice application logs)."""

from __future__ import annotations

import json
import re
import statistics
from collections import Counter
from typing import Any

from log_simulators.app.cli import LEVELS, SERVICES, main

from .conftest import generate

TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
TRACE_RE = re.compile(r"^[0-9a-f]{32}$")
SPAN_RE = re.compile(r"^[0-9a-f]{16}$")
CARD_RE = re.compile(r"\d{4}-\d{4}-\d{4}-\d{4}")
SSN_RE = re.compile(r"^\d{3}-\d{2}-\d{4}$")
HOST_RE = re.compile(r"^[a-z]+-[0-9a-f]{6}-[bcdfghjklmnpqrstvwxz2456789]{5}$")

REQUIRED_KEYS = {
    "timestamp",
    "level",
    "service",
    "version",
    "trace_id",
    "span_id",
    "seq",
    "msg",
    "duration_ms",
    "http",
    "user",
    "host",
}


def records(
    count: int = 300,
    seed: int = 42,
    extra: list[str] | None = None,
    backfill: str = "1h",
) -> list[dict[str, Any]]:
    lines = generate(main, count=count, seed=seed, extra=extra, backfill=backfill)
    assert len(lines) == count  # every event is exactly one line, even with stacks
    return [json.loads(line) for line in lines]


class TestFormat:
    def test_every_line_is_valid_ndjson_with_required_fields(self) -> None:
        for rec in records(count=400):
            assert rec.keys() >= REQUIRED_KEYS
            assert TS_RE.match(rec["timestamp"]), rec["timestamp"]
            assert rec["level"] in LEVELS
            assert rec["service"] in SERVICES
            assert rec["version"] == SERVICES[rec["service"]]
            assert TRACE_RE.match(rec["trace_id"])
            assert SPAN_RE.match(rec["span_id"])
            assert isinstance(rec["seq"], int)
            assert isinstance(rec["duration_ms"], int) and rec["duration_ms"] >= 1
            assert rec["http"]["method"] in {"GET", "POST", "DELETE"}
            assert rec["http"]["path"].startswith("/api/")
            assert 100 <= rec["http"]["status"] <= 599
            assert "@" in rec["user"]["email"]
            assert rec["user"]["id"].startswith("u-")
            assert HOST_RE.match(rec["host"]), rec["host"]

    def test_stack_traces_are_embedded_not_separate_lines(self) -> None:
        recs = records(count=2000)
        stacks = [r["error"]["stack"] for r in recs if "error" in r and "stack" in r["error"]]
        assert stacks, "expected some error records to carry a stack"
        for stack in stacks:
            assert "\n" in stack  # multi-frame, embedded in the JSON string
            assert "Traceback (most recent call last):" in stack or "\tat " in stack


class TestDeterminism:
    def test_same_seed_same_output(self) -> None:
        assert generate(main, count=80) == generate(main, count=80)

    def test_different_seed_differs(self) -> None:
        assert generate(main, count=80, seed=1) != generate(main, count=80, seed=2)


class TestDeliveryAndTracing:
    def test_seq_strictly_increasing_no_gaps(self) -> None:
        recs = records(count=500)
        assert [r["seq"] for r in recs] == list(range(len(recs)))

    def test_trace_ids_are_reused_across_events(self) -> None:
        traces = Counter(r["trace_id"] for r in records(count=500))
        assert traces.most_common(1)[0][1] > 1
        # but not collapsed into a handful of traces either
        assert len(traces) > 100


class TestRealism:
    def test_level_distribution(self) -> None:
        levels = Counter(r["level"] for r in records(count=1500))
        assert 0.60 < levels["info"] / 1500 < 0.80
        assert 0.08 < levels["debug"] / 1500 < 0.25
        assert 0.01 < levels["error"] / 1500 < 0.10

    def test_error_lines_get_error_object_and_5xx(self) -> None:
        for rec in records(count=1500):
            if rec["level"] == "error":
                assert rec["http"]["status"] >= 500
                assert rec["error"]["type"]
                assert rec["error"]["message"]
            else:
                assert rec["http"]["status"] < 500
                assert "error" not in rec

    def test_hosts_stable_per_service(self) -> None:
        per_service: dict[str, set[str]] = {}
        for rec in records(count=600):
            per_service.setdefault(rec["service"], set()).add(rec["host"])
        assert len(per_service) == len(SERVICES)  # every service shows up
        for svc, hosts in per_service.items():
            assert len(hosts) == 1  # pod name is stable per run
            assert next(iter(hosts)).startswith(f"{svc}-")

    def test_users_recur(self) -> None:
        users = Counter(r["user"]["id"] for r in records(count=500))
        assert users.most_common(1)[0][1] > 5  # zipf head user dominates

    def test_pii_baseline_rate_and_shape(self) -> None:
        recs = records(count=1500)
        pii = [r for r in recs if "payment" in r]
        assert 0.01 < len(pii) / len(recs) < 0.12  # ~5% of lines
        for rec in pii:
            assert CARD_RE.fullmatch(rec["payment"]["card"])
            assert SSN_RE.match(rec["user"]["ssn"])
            assert rec["user"]["phone"].startswith("+1-")
        # without the pii-leak scenario, PII never leaks into msg text
        assert not any(CARD_RE.search(r["msg"]) for r in recs)


class TestErrorStormScenario:
    def test_error_rate_measurably_higher(self) -> None:
        def error_rate(extra: list[str]) -> float:
            recs = records(count=1000, backfill="2h", extra=extra)
            return sum(r["level"] == "error" for r in recs) / len(recs)

        baseline = error_rate([])
        storm = error_rate(["--scenario", "error-storm"])
        assert baseline < 0.10
        assert storm > baseline * 2

    def test_errors_concentrate_in_one_service(self) -> None:
        recs = records(count=1000, backfill="2h", extra=["--scenario", "error-storm"])
        errors = Counter(r["service"] for r in recs if r["level"] == "error")
        top_service, top_count = errors.most_common(1)[0]
        assert top_count / sum(errors.values()) > 0.5
        storm_errors = [r for r in recs if r["level"] == "error" and r["service"] == top_service]
        cascade_types = {r["error"]["type"] for r in storm_errors}
        assert cascade_types <= {  # cascade failure modes, not random exceptions
            "TimeoutError",
            "ConnectionError",
            "CardDeclinedError",
            "IntegrityError",
            "ValidationError",
            "InvalidTokenError",
            "LockoutError",
            "KeyError",
            "RuntimeError",
            "SerializationError",
            "IOError",
            "SignatureError",
            "TokenError",
            "RenderError",
        }
        assert {"TimeoutError", "ConnectionError"} & cascade_types

    def test_error_durations_elevated(self) -> None:
        def error_durations(extra: list[str]) -> list[int]:
            recs = records(count=1000, backfill="2h", extra=extra)
            return [r["duration_ms"] for r in recs if r["level"] == "error"]

        baseline = statistics.median(error_durations([]))
        storm = statistics.median(error_durations(["--scenario", "error-storm"]))
        assert storm > baseline * 1.5


class TestPiiLeakScenario:
    def test_cards_leak_into_msg(self) -> None:
        recs = records(count=1000, backfill="2h", extra=["--scenario", "pii-leak"])
        leaked = [r for r in recs if CARD_RE.search(r["msg"])]
        assert len(leaked) / len(recs) > 0.25  # ~80% of lines inside leak windows
        for rec in leaked:
            assert "payment" in rec  # leak lines also carry the structured PII

    def test_pii_field_rate_elevated(self) -> None:
        recs = records(count=1000, backfill="2h", extra=["--scenario", "pii-leak"])
        pii_rate = sum("payment" in r for r in recs) / len(recs)
        assert pii_rate > 0.35  # vs ~5% baseline
