"""Timestamp and envelope formatting shared across simulators."""

from __future__ import annotations

from datetime import datetime

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def ncsa_clf(ts: datetime) -> str:
    """Apache CLF timestamp: 10/Oct/2000:13:55:36 -0700"""
    offset = ts.strftime("%z") or "+0000"
    return (
        f"{ts.day:02d}/{MONTHS[ts.month - 1]}/{ts.year}:"
        f"{ts.hour:02d}:{ts.minute:02d}:{ts.second:02d} {offset}"
    )


def rfc3164_ts(ts: datetime) -> str:
    """BSD syslog timestamp: 'Jun 10 22:14:15' (day is space-padded)."""
    return f"{MONTHS[ts.month - 1]} {ts.day:2d} {ts.strftime('%H:%M:%S')}"


def rfc5424_ts(ts: datetime) -> str:
    """RFC 5424 timestamp: 2026-06-10T22:14:15.003Z (millisecond precision)."""
    base = ts.strftime("%Y-%m-%dT%H:%M:%S") + f".{ts.microsecond // 1000:03d}"
    offset = ts.strftime("%z")
    if offset in ("+0000", ""):
        return base + "Z"
    return f"{base}{offset[:3]}:{offset[3:]}"


def iso_ms(ts: datetime) -> str:
    """ISO 8601 with milliseconds and offset: 2026-06-10T22:14:15.003+00:00"""
    return ts.isoformat(timespec="milliseconds")


def pri(facility: int, severity: int) -> int:
    """Syslog PRI value."""
    return facility * 8 + severity
