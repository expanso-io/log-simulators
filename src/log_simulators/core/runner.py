"""Shared run engine for all simulators.

Provides the common CLI contract (--rate, --count, --duration, --seed,
--backfill, --start-time, --output, --scenario, ...), Poisson-paced event
timing with optional diurnal shaping, backfill vs stream modes, and
end-of-run stats.

Every simulator supplies a ``make_event(ts, seq) -> str | None`` callable and
inherits identical ergonomics. Returning ``None`` skips an event (e.g. a
dropped sensor reading) while still consuming a time slot.
"""

from __future__ import annotations

import argparse
import contextlib
import math
import random
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from .sinks import Stats, open_sink

# Relative hourly traffic weights (UTC unless --tz given), normalized to a
# mean of 1.0 so --rate stays the average events/sec across a full day.
_DIURNAL_RAW = [
    0.25,
    0.18,
    0.14,
    0.12,
    0.14,
    0.22,  # 00-05  overnight trough
    0.40,
    0.70,
    1.10,
    1.45,
    1.60,
    1.65,  # 06-11  morning ramp
    1.55,
    1.50,
    1.60,
    1.65,
    1.55,
    1.35,  # 12-17  business-day plateau
    1.15,
    1.00,
    0.85,
    0.65,
    0.45,
    0.32,  # 18-23  evening decline
]
_MEAN = sum(_DIURNAL_RAW) / 24.0
DIURNAL = [w / _MEAN for w in _DIURNAL_RAW]

EventFn = Callable[[datetime, int], "str | None"]


def parse_duration(text: str) -> float:
    """Parse '30s', '5m', '2h', '1d', or bare seconds into seconds."""
    text = text.strip().lower()
    units = {"s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}
    if text and text[-1] in units:
        return float(text[:-1]) * units[text[-1]]
    return float(text)


@dataclass
class RunConfig:
    rate: float = 10.0
    count: int = 0  # 0 = unlimited
    duration: float | None = None  # seconds; wall-clock in stream, virtual in backfill
    seed: int | None = None
    output: str = "-"
    rotate_mb: int = 0
    backfill: float | None = None  # seconds of history to synthesize
    follow: bool = False  # continue streaming after backfill
    start_time: datetime | None = None  # anchor for backfill window (=> deterministic)
    tz: timezone | ZoneInfo = timezone.utc
    diurnal: bool = False
    quiet: bool = False
    extra: argparse.Namespace = field(default_factory=argparse.Namespace)

    def content_rng(self, salt: str = "content") -> random.Random:
        """Tool-facing RNG, independent of the engine's timing RNG."""
        return random.Random(f"{self.seed}-{salt}" if self.seed is not None else None)


def base_parser(prog: str, description: str, default_rate: float = 10.0) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=prog, description=description)
    p.add_argument(
        "--rate",
        type=float,
        default=default_rate,
        help=f"average events per second (default: {default_rate})",
    )
    p.add_argument(
        "--count",
        type=int,
        default=0,
        help="total event slots; tools may skip some (dropouts, batching); "
        "0 = unlimited (default: 0)",
    )
    p.add_argument(
        "--duration",
        type=parse_duration,
        default=None,
        metavar="DUR",
        help="stop after DUR (e.g. 30s, 5m, 2h); wall-clock when streaming, "
        "virtual time during a plain --backfill",
    )
    p.add_argument("--seed", type=int, default=None, help="seed for fully reproducible output")
    p.add_argument(
        "--output",
        default="-",
        metavar="DEST",
        help="'-' for stdout (default), a file path, tcp://host:port, or udp://host:port",
    )
    p.add_argument(
        "--rotate-mb",
        type=int,
        default=0,
        metavar="MB",
        help="rotate file output after MB megabytes (rotated files are gzipped)",
    )
    p.add_argument(
        "--backfill",
        type=parse_duration,
        default=None,
        metavar="DUR",
        help="synthesize DUR of historical logs at full speed, then exit",
    )
    p.add_argument(
        "--follow",
        action="store_true",
        help="after --backfill completes, continue streaming in real time",
    )
    p.add_argument(
        "--start-time",
        default=None,
        metavar="ISO8601",
        help="anchor the --backfill window at this time instead of now-DUR "
        "(makes output fully deterministic with --seed)",
    )
    p.add_argument(
        "--tz",
        default="UTC",
        metavar="ZONE",
        help="IANA timezone for timestamps and diurnal shaping (default: UTC)",
    )
    p.add_argument(
        "--diurnal",
        action="store_true",
        help="shape traffic volume by hour of day (overnight trough, midday peak)",
    )
    p.add_argument(
        "--quiet", action="store_true", help="suppress the end-of-run stats line on stderr"
    )
    return p


def config_from_args(args: argparse.Namespace) -> RunConfig:
    if args.tz.upper() == "UTC":
        tz: timezone | ZoneInfo = timezone.utc
    else:
        try:
            tz = ZoneInfo(args.tz)
        except Exception as exc:  # ZoneInfoNotFoundError, ValueError
            raise SystemExit(f"unknown timezone: {args.tz!r}") from exc
    start = None
    if args.start_time is not None:
        text = args.start_time.strip()
        if text.endswith(("Z", "z")):  # 3.10 fromisoformat has no Z support
            text = text[:-1] + "+00:00"
        try:
            start = datetime.fromisoformat(text)
        except ValueError as exc:
            raise SystemExit(f"invalid --start-time: {args.start_time!r} ({exc})") from exc
        if start.tzinfo is None:
            start = start.replace(tzinfo=tz)
        if args.backfill is None:
            print(
                "[logsim] warning: --start-time without --backfill anchors the live "
                "stream clock; output pauses until that wall-clock time is reached",
                file=sys.stderr,
            )
    return RunConfig(
        rate=args.rate,
        count=args.count,
        duration=args.duration,
        seed=args.seed,
        output=args.output,
        rotate_mb=args.rotate_mb,
        backfill=args.backfill,
        follow=args.follow,
        start_time=start,
        tz=tz,
        diurnal=args.diurnal,
        quiet=args.quiet,
        extra=args,
    )


def _multiplier(cfg: RunConfig, ts: datetime) -> float:
    if not cfg.diurnal:
        return 1.0
    return DIURNAL[ts.astimezone(cfg.tz).hour]


def run(cfg: RunConfig, make_event: EventFn) -> Stats:
    """Drive a simulator: pace events, route them to the sink, return stats."""
    if cfg.rate <= 0:
        raise SystemExit("--rate must be > 0")
    timing = random.Random(f"{cfg.seed}-timing" if cfg.seed is not None else None)
    stats = Stats(target_eps=cfg.rate)
    wall_start = time.monotonic()

    if cfg.backfill is not None:
        window_start = cfg.start_time or (datetime.now(cfg.tz) - timedelta(seconds=cfg.backfill))
        window_end = window_start + timedelta(seconds=cfg.backfill)
    else:
        window_start = cfg.start_time or datetime.now(cfg.tz)
        window_end = None

    virtual = window_start
    streaming = cfg.backfill is None
    seq = 0

    try:
        with open_sink(cfg.output, cfg.rotate_mb) as sink:
            while True:
                if cfg.count and seq >= cfg.count:
                    break
                gap = timing.expovariate(cfg.rate * _multiplier(cfg, virtual))
                virtual = virtual + timedelta(seconds=gap)

                if not streaming and window_end is not None and virtual >= window_end:
                    if not cfg.follow:
                        break
                    streaming = True
                    virtual = datetime.now(cfg.tz)

                if streaming:
                    now = datetime.now(cfg.tz)
                    lag = (virtual - now).total_seconds()
                    if cfg.duration is not None:
                        remaining = cfg.duration - (time.monotonic() - wall_start)
                        if remaining <= 0 or lag >= remaining:
                            # never sleep past the deadline waiting for one more event
                            if remaining > 0:
                                time.sleep(remaining)
                            break
                    if lag > 0:
                        time.sleep(lag)
                    else:
                        # fell behind (slow consumer / high rate): don't accumulate debt
                        virtual = now
                elif (
                    not cfg.follow
                    and cfg.duration is not None
                    and (virtual - window_start).total_seconds() >= cfg.duration
                ):
                    # plain backfill: --duration caps the virtual window. With
                    # --follow it instead caps the wall-clock streaming phase
                    # (backfill itself takes near-zero wall time).
                    break

                event = make_event(virtual.astimezone(cfg.tz), seq)
                seq += 1
                if event is None:
                    continue
                stats.record(sink.write(event), event)
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        # downstream (e.g. `| head`) closed the pipe; that's a clean stop
        with contextlib.suppress(Exception):
            sys.stdout.close()

    stats.finish(time.monotonic() - wall_start)
    if not cfg.quiet:
        print(stats.summary(), file=sys.stderr)
    return stats


def jitter_sleep_hint() -> float:
    """Exposed for tests; placeholder for future adaptive pacing."""
    return 0.0


def clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def sin_ramp(progress: float) -> float:
    """Smooth 0->1->0 ramp over progress in [0, 1]; used for burst intensity."""
    return math.sin(math.pi * clamp(progress, 0.0, 1.0))
