"""Tests for logsim-postgres (PostgreSQL stderr / csvlog / jsonlog server logs)."""

from __future__ import annotations

import csv
import json
import re
from collections import Counter
from datetime import datetime
from itertools import pairwise

from log_simulators.postgres.cli import main

from .conftest import generate

# log_line_prefix '%m [%p] %q%u@%d ' followed by a severity tag. Background
# processes (checkpointer, autovacuum, postmaster) have no user@db part.
PREFIX_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} \w+) \[(\d+)\] "
    r"(?:[\w\[\]]+@[\w\[\]]+ )?"
    r"(LOG|ERROR|FATAL|WARNING|DETAIL|HINT|STATEMENT):  \S.*$"
)
HEADER_SEVERITIES = {"LOG", "ERROR", "FATAL", "WARNING"}
CONTINUATION_SEVERITIES = {"DETAIL", "HINT", "STATEMENT"}
DEADLOCK_DETAIL_RE = re.compile(
    r"DETAIL:  Process (\d+) waits for ShareLock on transaction \d+; "
    r"blocked by process (\d+)\.$"
)
# Full fixed-width PG14+ csvlog schema: log_time .. query_id.
CSV_COLUMNS = 26
CKPT_TOTAL_RE = re.compile(r"total=(\d+\.\d{3}) s")
CKPT_COMPLETE_RE = re.compile(
    r"checkpoint complete: wrote \d+ buffers \(\d+\.\d%\); "
    r"\d+ WAL file\(s\) added, \d+ removed, \d+ recycled; "
    r"write=\d+\.\d{3} s, sync=\d+\.\d{3} s, total=\d+\.\d{3} s; "
)


def reassemble(lines: list[str]) -> list[list[str]]:
    """Group stderr lines into events: a new event starts at LOG/ERROR/FATAL/WARNING."""
    events: list[list[str]] = []
    for line in lines:
        match = PREFIX_RE.match(line)
        assert match, line
        if match.group(3) in HEADER_SEVERITIES:
            events.append([line])
        else:
            assert events, f"continuation before any header: {line}"
            events[-1].append(line)
    return events


def _meta(line: str) -> tuple[str, str, str]:
    """(timestamp, pid, severity) of one stderr line."""
    match = PREFIX_RE.match(line)
    assert match, line
    return match.group(1), match.group(2), match.group(3)


def _ts_of(line: str) -> datetime:
    """Parse the %m timestamp of one stderr line (timezone name dropped)."""
    return datetime.strptime(_meta(line)[0].rsplit(" ", 1)[0], "%Y-%m-%d %H:%M:%S.%f")


class TestStderrFormat:
    def test_every_line_matches_prefix(self) -> None:
        for line in generate(main, count=300):
            assert PREFIX_RE.match(line), line

    def test_error_events_have_continuations(self) -> None:
        events = reassemble(generate(main, count=600))
        errors = [e for e in events if _meta(e[0])[2] == "ERROR"]
        assert len(errors) > 10
        for event in errors:
            assert len(event) >= 2, event
            ts, pid, _ = _meta(event[0])
            for cont in event[1:]:
                cts, cpid, sev = _meta(cont)
                assert sev in CONTINUATION_SEVERITIES
                assert (cts, cpid) == (ts, pid), event

    def test_checkpoint_pairs_track_virtual_clock(self) -> None:
        # ~40 virtual minutes at 1 event/s so several ~5-minute cycles fit.
        lines = generate(main, count=2400, backfill="2h", extra=["--rate", "1"])
        timeline: list[tuple[str, datetime, float, str]] = []
        for line in lines:
            if "checkpoint starting:" in line:
                timeline.append(("start", _ts_of(line), 0.0, _meta(line)[1]))
            elif "checkpoint complete:" in line:
                assert CKPT_COMPLETE_RE.search(line), line
                m = CKPT_TOTAL_RE.search(line)
                assert m, line
                timeline.append(("complete", _ts_of(line), float(m.group(1)), _meta(line)[1]))
        # starting/complete strictly alternate; a trailing start may be cut off
        assert timeline and timeline[0][0] == "start"
        for (kind_a, *_), (kind_b, *_) in pairwise(timeline):
            assert kind_a != kind_b, timeline
        assert len({pid for *_, pid in timeline}) == 1  # one checkpointer pid
        pairs = list(zip(timeline[::2], timeline[1::2], strict=False))
        assert len(pairs) >= 4
        for (_, start_ts, _, _), (_, complete_ts, total, _) in pairs:
            elapsed = (complete_ts - start_ts).total_seconds()
            # complete only fires once the claimed total has elapsed in
            # event timestamps (small slack for millisecond truncation)
            assert elapsed >= total - 0.05, (start_ts, complete_ts, total)
        starts = [ts for kind, ts, _, _ in timeline if kind == "start"]
        for a, b in pairwise(starts):
            assert (b - a).total_seconds() >= 30.0, (a, b)

    def test_connection_authorized_follows_received(self) -> None:
        events = reassemble(generate(main, count=600))
        received = 0
        for i, event in enumerate(events):
            if "connection received:" not in event[0]:
                continue
            if i + 1 >= len(events):
                continue
            follower = events[i + 1][0]
            assert "connection authorized:" in follower, follower
            assert _meta(event[0])[1] == _meta(follower)[1]  # same backend pid
            received += 1
        assert received >= 5


class TestCsvlog:
    def test_csvlog_every_row_has_26_fields(self) -> None:
        lines = generate(main, count=500, extra=["--format", "csvlog"])
        rows = list(csv.reader(lines))
        assert len(rows) == len(lines)
        for row in rows:
            assert len(row) == 26, row  # fixed-width PG14+ csvlog schema

    def test_csvlog_parses_with_constant_columns(self) -> None:
        lines = generate(main, count=300, extra=["--format", "csvlog"])
        rows = list(csv.reader(lines))
        assert len(rows) == len(lines)
        for row in rows:
            assert len(row) == CSV_COLUMNS, row
            assert re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} \w+$", row[0])
            assert row[3].isdigit()  # pid
            if row[4]:  # connection_from is host:port or empty
                assert re.match(r"^[\d.]+:\d+$", row[4]), row
            assert row[11] in {"LOG", "ERROR", "FATAL", "WARNING"}  # severity
            assert re.match(r"^[0-9A-Z]{5}$", row[12])  # sql state code
            assert row[13]  # message never empty
            assert row[16] == ""  # internal_query
            assert row[17] == ""  # internal_query_pos
            assert row[18] == ""  # context
            assert row[20] == ""  # query_pos
            assert row[21] == ""  # location
            assert row[23]  # backend_type never empty
            assert row[24] == ""  # leader_pid
            assert row[25] == "0"  # query_id (compute_query_id off)

    def test_csvlog_errors_carry_detail_and_query(self) -> None:
        lines = generate(main, count=600, extra=["--format", "csvlog"])
        errors = [row for row in csv.reader(lines) if row[11] == "ERROR"]
        assert errors
        assert any(row[14] for row in errors)  # detail column populated
        assert all(row[19] for row in errors)  # query column carries the statement


class TestJsonlog:
    def test_jsonlog_parses(self) -> None:
        for line in generate(main, count=300, extra=["--format", "jsonlog"]):
            record = json.loads(line)
            assert {"timestamp", "pid", "error_severity", "message", "backend_type"} <= (
                record.keys()
            )
            assert record["error_severity"] in {"LOG", "ERROR", "FATAL", "WARNING"}
            assert isinstance(record["pid"], int)

    def test_jsonlog_remote_host_and_port_are_separate(self) -> None:
        records = [
            json.loads(line) for line in generate(main, count=400, extra=["--format", "jsonlog"])
        ]
        with_remote = [r for r in records if "remote_host" in r]
        assert with_remote
        for record in with_remote:
            assert re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", record["remote_host"]), record
            assert isinstance(record["remote_port"], int), record
            assert 1 <= record["remote_port"] <= 65535


class TestDeterminism:
    def test_same_seed_same_output(self) -> None:
        assert generate(main, count=80) == generate(main, count=80)

    def test_different_seed_differs(self) -> None:
        assert generate(main, count=80, seed=1) != generate(main, count=80, seed=2)


class TestRealism:
    def test_duration_values_in_range(self) -> None:
        durations = [
            int(m.group(1))
            for line in generate(main, count=600)
            if (m := re.search(r"LOG:  duration: (\d+)\.\d{3} ms  statement: ", line))
        ]
        assert len(durations) > 50
        assert all(50 <= ms <= 30_000 for ms in durations)

    def test_backend_pids_recur(self) -> None:
        pids = Counter(_meta(e[0])[1] for e in reassemble(generate(main, count=500)))
        assert pids.most_common(1)[0][1] > 5

    def test_users_and_dbs_are_consistent_pool(self) -> None:
        who_re = re.compile(r"\[\d+\] ([\w\[\]]+)@([\w\[\]]+) ")
        users, dbs = set(), set()
        for line in generate(main, count=500):
            if m := who_re.search(line):
                users.add(m.group(1))
                dbs.add(m.group(2))
        assert users <= {"app_user", "analytics_ro", "admin", "[unknown]"}
        assert dbs <= {"shopdb", "analytics", "[unknown]"}
        assert "app_user" in users and "shopdb" in dbs

    def test_disconnection_reports_session_time(self) -> None:
        lines = [line for line in generate(main, count=600) if "disconnection:" in line]
        assert lines
        for line in lines:
            assert re.search(
                r"disconnection: session time: \d+:\d{2}:\d{2}\.\d{3} "
                r"user=\w+ database=\w+ host=[\d.]+ port=\d+$",
                line,
            ), line


class TestScenario:
    @staticmethod
    def _deadlock_rate(extra: list[str]) -> float:
        events = reassemble(generate(main, count=800, backfill="2h", extra=extra))
        return sum("deadlock detected" in e[0] for e in events) / len(events)

    def test_deadlock_scenario_raises_rate(self) -> None:
        baseline = self._deadlock_rate([])
        storm = self._deadlock_rate(["--scenario", "deadlock"])
        assert baseline < 0.05
        assert storm > 0.10
        assert storm > baseline * 4

    def test_deadlock_pairs_are_reciprocal(self) -> None:
        lines = generate(main, count=800, backfill="2h", extra=["--scenario", "deadlock"])
        pairs = {
            (m.group(1), m.group(2)) for line in lines if (m := DEADLOCK_DETAIL_RE.search(line))
        }
        reciprocal = [(a, b) for (a, b) in pairs if (b, a) in pairs]
        assert len(pairs) >= 10
        assert reciprocal, "expected at least one reciprocal blocked-by pid pair"
