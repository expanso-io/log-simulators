"""Shared engine for all log simulators: CLI contract, pacing, entities,
scenario scheduling, formats, and output sinks."""

from .entities import (
    USER_AGENTS,
    hostnames,
    internal_ips,
    lognormal_int,
    make_faker,
    pick,
    public_ips,
    usernames,
    zipf_weights,
)
from .formats import iso_ms, ncsa_clf, pri, rfc3164_ts, rfc5424_ts
from .runner import (
    DIURNAL,
    EventFn,
    RunConfig,
    base_parser,
    clamp,
    config_from_args,
    parse_duration,
    run,
    sin_ramp,
)
from .scenario import BurstSchedule
from .sinks import Sink, Stats, open_sink

__all__ = [
    "DIURNAL",
    "USER_AGENTS",
    "BurstSchedule",
    "EventFn",
    "RunConfig",
    "Sink",
    "Stats",
    "base_parser",
    "clamp",
    "config_from_args",
    "hostnames",
    "internal_ips",
    "iso_ms",
    "lognormal_int",
    "make_faker",
    "ncsa_clf",
    "open_sink",
    "parse_duration",
    "pick",
    "pri",
    "public_ips",
    "rfc3164_ts",
    "rfc5424_ts",
    "run",
    "sin_ramp",
    "usernames",
    "zipf_weights",
]
