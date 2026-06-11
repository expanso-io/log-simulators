"""Deterministic anomaly/scenario scheduling.

Demos sell on the story of catching an anomaly at the edge, not on raw
volume. A ``BurstSchedule`` opens recurring anomaly windows derived purely
from epoch time, so the same windows appear whether you backfill history or
stream live, and reruns with the same timestamps are reproducible.

Each tool interprets "active" its own way: a 4625 brute-force flood, a port
scan, a 5xx error storm, a sensor pressure spike, ...
"""

from __future__ import annotations

from datetime import datetime

from .runner import sin_ramp


class BurstSchedule:
    """Recurring burst windows: every ``period`` seconds, ``length`` seconds hot."""

    def __init__(self, period: float = 600.0, length: float = 45.0, phase: float = 0.0) -> None:
        if length >= period:
            raise ValueError("burst length must be shorter than its period")
        self.period = period
        self.length = length
        self.phase = phase

    def _offset(self, ts: datetime) -> float:
        return (ts.timestamp() + self.phase) % self.period

    def active(self, ts: datetime) -> bool:
        return self._offset(ts) < self.length

    def intensity(self, ts: datetime) -> float:
        """0 outside a burst; ramps 0 -> 1 -> 0 across the window."""
        off = self._offset(ts)
        if off >= self.length:
            return 0.0
        return sin_ramp(off / self.length)
