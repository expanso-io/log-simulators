"""Tests for the shared engine: pacing, sinks, scenario, formats, entities."""

from __future__ import annotations

import gzip
import itertools
import random
import time
from datetime import datetime, timedelta, timezone

import pytest

from log_simulators.core import (
    DIURNAL,
    BurstSchedule,
    RunConfig,
    Stats,
    ncsa_clf,
    parse_duration,
    pri,
    rfc3164_ts,
    rfc5424_ts,
    run,
    zipf_weights,
)
from log_simulators.core.sinks import FileSink

UTC = timezone.utc
START = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


class TestParseDuration:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [("30s", 30.0), ("5m", 300.0), ("2h", 7200.0), ("1d", 86400.0), ("45", 45.0)],
    )
    def test_units(self, text: str, expected: float) -> None:
        assert parse_duration(text) == expected

    def test_garbage_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_duration("soon")


class TestDiurnal:
    def test_mean_is_one(self) -> None:
        assert sum(DIURNAL) / 24 == pytest.approx(1.0)

    def test_trough_vs_peak(self) -> None:
        assert min(DIURNAL) < 0.3 < 1.0 < max(DIURNAL)


class TestZipf:
    def test_monotone_decreasing(self) -> None:
        w = zipf_weights(10)
        assert all(a > b for a, b in itertools.pairwise(w))


class TestBurstSchedule:
    def test_active_window(self) -> None:
        sched = BurstSchedule(period=600, length=60)
        base = datetime.fromtimestamp(600 * 1000, tz=UTC)  # exactly on a period boundary
        assert sched.active(base)
        assert sched.active(base + timedelta(seconds=59))
        assert not sched.active(base + timedelta(seconds=61))
        assert sched.active(base + timedelta(seconds=600))  # recurs next period

    def test_intensity_ramps(self) -> None:
        sched = BurstSchedule(period=600, length=60)
        base = datetime.fromtimestamp(600 * 1000, tz=UTC)
        mid = sched.intensity(base + timedelta(seconds=30))
        edge = sched.intensity(base + timedelta(seconds=5))
        assert mid == pytest.approx(1.0)
        assert 0 < edge < mid
        assert sched.intensity(base + timedelta(seconds=120)) == 0.0

    def test_length_must_be_shorter(self) -> None:
        with pytest.raises(ValueError):
            BurstSchedule(period=10, length=10)


def _run_collect(cfg: RunConfig) -> tuple[list[datetime], Stats]:
    seen: list[datetime] = []

    def make_event(ts: datetime, seq: int) -> str:
        seen.append(ts)
        return f"event {seq}"

    stats = run(cfg, make_event)
    return seen, stats


class TestRunEngine:
    def test_backfill_window_and_count(self, capsys: pytest.CaptureFixture[str]) -> None:
        cfg = RunConfig(rate=100, count=50, seed=1, backfill=3600, start_time=START, quiet=True)
        seen, stats = _run_collect(cfg)
        assert stats.events == 50
        assert all(START <= ts <= START + timedelta(hours=1) for ts in seen)
        assert seen == sorted(seen)  # monotonic timestamps

    def test_backfill_exhausts_window(self) -> None:
        cfg = RunConfig(rate=1.0, seed=2, backfill=60, start_time=START, quiet=True)
        seen, stats = _run_collect(cfg)
        # ~60 events expected for 60s at 1 eps; Poisson spread, generous bounds
        assert 20 <= stats.events <= 120
        assert seen[-1] <= START + timedelta(seconds=60)

    def test_deterministic_with_seed(self) -> None:
        def cfg() -> RunConfig:
            return RunConfig(rate=50, count=30, seed=7, backfill=600, start_time=START, quiet=True)

        first, _ = _run_collect(cfg())
        second, _ = _run_collect(cfg())
        assert first == second

    def test_none_event_skips_but_advances(self) -> None:
        emitted: list[int] = []

        def make_event(ts: datetime, seq: int) -> str | None:
            if seq % 2 == 0:
                return None
            emitted.append(seq)
            return "x"

        cfg = RunConfig(rate=100, count=10, seed=3, backfill=60, start_time=START, quiet=True)
        stats = run(cfg, make_event)
        assert stats.events == 5
        assert emitted == [1, 3, 5, 7, 9]

    def test_stream_mode_respects_duration_and_rate(self) -> None:
        cfg = RunConfig(rate=200, duration=0.5, seed=4, quiet=True)
        _, stats = _run_collect(cfg)
        # 200 eps for 0.5s -> ~100 events; allow wide Poisson/scheduling slack
        assert 40 <= stats.events <= 220

    def test_duration_deadline_not_overshot_at_low_rate(self) -> None:
        # mean inter-event gap is 10s; the run must still stop at ~0.4s
        cfg = RunConfig(rate=0.1, duration=0.4, seed=11, quiet=True)
        started = time.monotonic()
        _run_collect(cfg)
        assert time.monotonic() - started < 3.0

    def test_backfill_follow_duration_streams_after_backfill(self) -> None:
        # without the follow fix, --duration <= backfill window exits mid-backfill
        cfg = RunConfig(rate=50, duration=0.3, seed=12, backfill=2.0, follow=True, quiet=True)
        started = time.monotonic()
        seen, stats = _run_collect(cfg)
        assert time.monotonic() - started < 3.0
        assert stats.events > 50  # the full ~100-event backfill window was emitted
        # and at least one event came from the live streaming phase (recent wall clock)
        assert (datetime.now(UTC) - seen[-1]).total_seconds() < 10

    def test_stats_summary_format(self) -> None:
        cfg = RunConfig(rate=100, count=10, seed=5, backfill=60, start_time=START, quiet=True)
        _, stats = _run_collect(cfg)
        line = stats.summary()
        assert "events=10" in line
        assert "target_eps=100" in line


class TestStats:
    def test_multiline_event_counts_lines(self) -> None:
        stats = Stats()
        stats.record(20, "line1\nline2\nline3")
        assert stats.events == 1
        assert stats.lines == 3
        assert stats.bytes == 20


class TestFileSink:
    def test_writes_and_rotates(self, tmp_path) -> None:
        path = tmp_path / "app.log"
        sink = FileSink(str(path), rotate_mb=1, keep=2)
        payload = "x" * 4096
        for _ in range(300):  # ~1.2 MB
            sink.write(payload)
        sink.close()
        rotated = path.with_name("app.log.1.gz")
        assert rotated.exists()
        with gzip.open(rotated, "rt") as fh:
            assert fh.readline().startswith("xxxx")
        assert path.exists()


class TestFormats:
    def test_ncsa_clf(self) -> None:
        assert ncsa_clf(START) == "15/Jan/2026:12:00:00 +0000"

    def test_rfc3164_space_pads_day(self) -> None:
        assert rfc3164_ts(datetime(2026, 6, 5, 1, 2, 3)) == "Jun  5 01:02:03"
        assert rfc3164_ts(datetime(2026, 6, 15, 1, 2, 3)) == "Jun 15 01:02:03"

    def test_rfc5424_utc(self) -> None:
        ts = datetime(2026, 6, 10, 22, 14, 15, 3000, tzinfo=UTC)
        assert rfc5424_ts(ts) == "2026-06-10T22:14:15.003Z"

    def test_pri(self) -> None:
        assert pri(16, 5) == 133  # local0.notice

    def test_rng_independence(self) -> None:
        cfg = RunConfig(seed=42)
        a = cfg.content_rng().random()
        b = random.Random("42-timing").random()
        assert a != b


class TestCliErrors:
    def _args(self, **overrides: str) -> RunConfig:
        from log_simulators.core import base_parser, config_from_args

        argv = []
        for key, value in overrides.items():
            argv += [f"--{key.replace('_', '-')}", value]
        return config_from_args(base_parser("t", "t").parse_args(argv))

    def test_bad_tz_exits_cleanly(self) -> None:
        with pytest.raises(SystemExit, match="unknown timezone"):
            self._args(tz="Nonsense/Zone")

    def test_bad_start_time_exits_cleanly(self) -> None:
        with pytest.raises(SystemExit, match="invalid --start-time"):
            self._args(start_time="2026-99-99", backfill="1h")

    def test_z_suffix_start_time_parses(self) -> None:
        cfg = self._args(start_time="2026-01-15T12:00:00Z", backfill="1h")
        assert cfg.start_time is not None
        assert cfg.start_time.utcoffset() == timedelta(0)


class TestUdpSink:
    def test_oversized_event_truncated_not_crashed(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from log_simulators.core.sinks import UdpSink

        sink = UdpSink("127.0.0.1", 9)
        nbytes = sink.write("x" * 70_000)
        sink.close()
        assert 0 < nbytes <= 65_000
        assert "truncated" in capsys.readouterr().err
