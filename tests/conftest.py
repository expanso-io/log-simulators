"""Shared test helpers.

The standard way to test a simulator deterministically:

    lines = generate(main, count=200)

which runs the tool's ``main`` with a fixed seed and a fixed --start-time
backfill window, so output is fully reproducible and timestamp-stable.
"""

from __future__ import annotations

import contextlib
import io
from collections.abc import Callable

import pytest

FIXED_START = "2026-01-15T12:00:00+00:00"


def invoke(main: Callable[[list[str] | None], int], args: list[str]) -> list[str]:
    """Run a simulator main() capturing stdout; returns emitted lines."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(args)
    assert rc == 0
    out = buf.getvalue()
    return out.splitlines()


def generate(
    main: Callable[[list[str] | None], int],
    count: int = 100,
    seed: int = 42,
    extra: list[str] | None = None,
    backfill: str = "1h",
) -> list[str]:
    """Deterministic generation: fixed seed + anchored backfill window."""
    args = [
        "--seed",
        str(seed),
        "--count",
        str(count),
        "--backfill",
        backfill,
        "--start-time",
        FIXED_START,
        "--rate",
        "10",
        "--quiet",
    ]
    return invoke(main, args + (extra or []))


@pytest.fixture
def fixed_start() -> str:
    return FIXED_START
