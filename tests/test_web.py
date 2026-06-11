"""Tests for logsim-web (Apache/nginx access and error logs)."""

from __future__ import annotations

import json
import re
from collections import Counter

from log_simulators.web.cli import main

from .conftest import generate

COMBINED_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3} - \S+ "
    r"\[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "
    r'"(GET|POST) \S+ HTTP/1\.1" \d{3} (\d+|-) "[^"]*" "[^"]*"$'
)
COMMON_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3} - \S+ "
    r"\[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "
    r'"(GET|POST) \S+ HTTP/1\.1" \d{3} (\d+|-)$'
)
NGINX_ERROR_RE = re.compile(
    r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[(error|warn|crit)\] \d+#\d+: \*\d+ .*"
    r'client: (\d{1,3}\.){3}\d{1,3}, server: \S+, request: "GET \S+ HTTP/1\.1", '
    r'host: "[^"]+"$'
)


def _status(line: str) -> int:
    return int(line.split('" ')[1].split()[0])


class TestFormats:
    def test_combined_lines_match_ncsa(self) -> None:
        for line in generate(main, count=300):
            assert COMBINED_RE.match(line), line

    def test_common_format(self) -> None:
        for line in generate(main, count=100, extra=["--format", "common"]):
            assert COMMON_RE.match(line), line

    def test_json_format_parses(self) -> None:
        for line in generate(main, count=100, extra=["--format", "json"]):
            record = json.loads(line)
            assert {
                "timestamp",
                "client_ip",
                "method",
                "path",
                "status",
                "bytes",
                "user_agent",
            } <= record.keys()
            assert 100 <= record["status"] <= 599

    def test_nginx_error_format(self) -> None:
        for line in generate(main, count=100, extra=["--format", "nginx-error"]):
            assert NGINX_ERROR_RE.match(line), line

    def test_304_bytes_field_is_dash_in_text_formats(self) -> None:
        """Apache %b convention: zero-byte (304) responses log '-', never '0'."""
        for fmt in ("combined", "common"):
            saw_304 = False
            for line in generate(main, count=2000, extra=["--format", fmt]):
                status, bytes_field = line.split('" ')[1].split()[:2]
                if status == "304":
                    saw_304 = True
                    assert bytes_field == "-", line
                else:
                    assert bytes_field.isdigit() and bytes_field != "0", line
            assert saw_304, f"no 304 responses generated for format {fmt}"

    def test_json_304_keeps_integer_zero_bytes(self) -> None:
        records = [
            json.loads(line) for line in generate(main, count=2000, extra=["--format", "json"])
        ]
        not_modified = [r for r in records if r["status"] == 304]
        assert not_modified, "no 304 responses generated"
        for record in not_modified:
            assert isinstance(record["bytes"], int)
            assert record["bytes"] == 0


class TestDeterminism:
    def test_same_seed_same_output(self) -> None:
        assert generate(main, count=50) == generate(main, count=50)

    def test_different_seed_differs(self) -> None:
        assert generate(main, count=50, seed=1) != generate(main, count=50, seed=2)


class TestRealism:
    def test_status_distribution_mostly_2xx(self) -> None:
        statuses = Counter(_status(line) for line in generate(main, count=1000))
        assert statuses[200] / 1000 > 0.6
        assert sum(v for k, v in statuses.items() if k >= 500) / 1000 < 0.05

    def test_entity_consistency_users_recur(self) -> None:
        users = Counter(line.split()[2] for line in generate(main, count=500))
        users.pop("-", None)
        assert users and users.most_common(1)[0][1] > 1

    def test_sessions_walk_real_paths(self) -> None:
        paths = [line.split('"')[1].split()[1] for line in generate(main, count=500)]
        assert any(p.startswith("/products") for p in paths)
        assert any(p.startswith("/static/") or p == "/favicon.ico" for p in paths)


class TestScenario:
    def test_error_storm_raises_5xx_rate(self) -> None:
        def rate_5xx(extra: list[str]) -> float:
            lines = generate(main, count=800, backfill="2h", extra=extra)
            statuses = [_status(line) for line in lines]
            return sum(s >= 500 for s in statuses) / len(statuses)

        baseline = rate_5xx([])
        storm = rate_5xx(["--scenario", "error-storm"])
        assert baseline < 0.04
        assert storm > baseline * 2
