"""Tests for logsim-k8s (Kubernetes CRI/containerd container logs)."""

from __future__ import annotations

import json
import re
from collections import Counter

from log_simulators.k8s.cli import main

from .conftest import generate

CRI_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.(\d{9})Z (stdout|stderr) ([FP]) (.+)$")
KLOG_RE = re.compile(r"^[IWE]\d{4} \d{2}:\d{2}:\d{2}\.\d{6} +1 [a-z_]+\.go:\d+\] .+$")
POD_NAME_RE = re.compile(r"^(frontend|payments|prometheus)(-[bcdfghjklmnpqrstvwxz2456789]+){1,2}$")
ACCESS_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3} - - \[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "
    r'"(GET|POST|PUT|DELETE) \S+ HTTP/1\.1" \d{3} \d+ "-" "[^"]*" \d+ \d+\.\d{3} '
    r"\[shop-frontend-80\] \[\] (\d{1,3}\.){3}\d{1,3}:8080 \d+ \d+\.\d{3} \d{3} [0-9a-f]{16}$"
)


def parse(line: str) -> tuple[str, str, str, str]:
    """Split a CRI record into (nanos, stream, tag, payload)."""
    m = CRI_RE.match(line)
    assert m, line
    return m.group(1), m.group(2), m.group(3), m.group(4)


def reassemble(lines: list[str]) -> list[tuple[str, str, int]]:
    """Rebuild logical lines: P chunks concatenate until their final F record.

    Returns (stream, full_payload, n_chunks) per logical line, asserting the
    CRI partial-line invariants along the way (chains stay on one stream and
    always terminate in an F record).
    """
    events: list[tuple[str, str, int]] = []
    buf = ""
    chunks = 0
    buf_stream: str | None = None
    for line in lines:
        _, stream, tag, payload = parse(line)
        if buf_stream is not None:
            assert stream == buf_stream, "partial continuation switched streams"
        buf += payload
        chunks += 1
        if tag == "F":
            events.append((stream, buf, chunks))
            buf, chunks, buf_stream = "", 0, None
        else:
            buf_stream = stream
    assert buf == "", "output ended with a dangling P record"
    return events


class TestFormat:
    def test_every_line_matches_cri(self) -> None:
        for line in generate(main, count=400):
            m = CRI_RE.match(line)
            assert m, line
            assert len(m.group(1)) == 9  # nanosecond field has exactly 9 digits

    def test_json_payloads_parse(self) -> None:
        payloads = [p for _, p, _ in reassemble(generate(main, count=400)) if p.startswith("{")]
        assert payloads
        for payload in payloads:
            doc = json.loads(payload)
            assert {"level", "ts", "msg"} <= doc.keys()
            assert doc["level"] in {"info", "warn", "error"}

    def test_klog_lines_match_klog_format(self) -> None:
        klog = [
            (s, p)
            for s, p, _ in reassemble(generate(main, count=600))
            if re.match(r"^[IWE]\d{4} ", p)
        ]
        assert klog, "expected klog payloads from kube-system pods"
        for stream, payload in klog:
            assert KLOG_RE.match(payload), payload
            assert stream == "stderr"  # klog writes to stderr

    def test_ingress_access_payloads(self) -> None:
        access = [
            p for _, p, _ in reassemble(generate(main, count=600)) if re.match(r"^\d{1,3}\.", p)
        ]
        assert access, "expected access-log payloads from the ingress pod"
        for payload in access:
            assert ACCESS_RE.match(payload), payload

    def test_partial_chunks_reassemble_to_json(self) -> None:
        lines = generate(main, count=1500)
        split = [(s, p, n) for s, p, n in reassemble(lines) if n > 1]
        assert split, "expected ~3% of events to be split into P/.../F records"
        for _, payload, n in split:
            assert 2 <= n <= 3
            doc = json.loads(payload)  # chunks concatenate back into valid JSON
            assert doc["msg"] == "request body accepted"
        # P records exist on the wire and each is eventually closed by an F
        tags = [parse(line)[2] for line in lines]
        assert "P" in tags
        assert tags[-1] == "F"


class TestDeterminism:
    def test_same_seed_same_output(self) -> None:
        assert generate(main, count=300) == generate(main, count=300)

    def test_different_seed_differs(self) -> None:
        assert generate(main, count=300, seed=1) != generate(main, count=300, seed=2)


class TestScenario:
    def test_crash_loop_panic_and_restart(self) -> None:
        baseline = generate(main, count=800, backfill="2h", extra=["--pod-field"])
        assert not any("panic:" in line for line in baseline)

        lines = generate(
            main, count=800, backfill="2h", extra=["--scenario", "crash-loop", "--pod-field"]
        )
        panic_lines = [line for line in lines if "panic: runtime error" in line]
        assert panic_lines, "crash-loop must emit a Go panic inside the burst window"
        for line in panic_lines:
            _, stream, tag, payload = parse(line)
            assert (stream, tag) == ("stderr", "F")
            assert "invalid memory address" in payload
        assert any("goroutine" in line and "[running]" in line for line in lines)
        assert any("/usr/local/go/src/net/http/server.go" in line for line in lines)

        restarts = [
            json.loads(parse(line)[3]) for line in lines if "Starting server on :8080" in line
        ]
        assert restarts, "crashed pod must log restart lines after the burst window"
        assert len({doc["pod"] for doc in restarts}) == 1  # always the same pod


class TestRealism:
    def test_pod_identity_recurs(self) -> None:
        names: Counter[str] = Counter()
        for _, payload, _ in reassemble(generate(main, count=600, extra=["--pod-field"])):
            if payload.startswith("{"):
                doc = json.loads(payload)
                names[doc["pod"]] += 1
                assert POD_NAME_RE.match(doc["pod"]), doc["pod"]
                assert doc["namespace"] in {"shop", "monitoring"}
        assert 3 <= len(names) <= 10  # a handful of stable pods, not fresh names
        assert names.most_common(1)[0][1] > 10  # the same pods recur heavily

    def test_stream_correlates_with_level(self) -> None:
        for stream, payload, _ in reassemble(generate(main, count=500)):
            if payload.startswith("{"):
                doc = json.loads(payload)
                assert stream == ("stdout" if doc["level"] == "info" else "stderr")

    def test_levels_mostly_info(self) -> None:
        levels: Counter[str] = Counter(
            json.loads(p)["level"]
            for _, p, _ in reassemble(generate(main, count=800))
            if p.startswith("{")
        )
        total = sum(levels.values())
        assert levels["info"] / total > 0.55
        assert levels["error"] / total < 0.12
