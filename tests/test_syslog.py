"""Tests for logsim-syslog (RFC 3164 / RFC 5424 syslog)."""

from __future__ import annotations

import re
from collections import Counter

from log_simulators.syslog.cli import main

from .conftest import generate

RFC5424_RE = re.compile(
    r"^<\d{1,3}>1 "
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}(Z|[+-]\d{2}:\d{2}) "
    r"[a-z0-9][a-z0-9.-]* "  # hostname
    r"[A-Za-z0-9/._-]+ "  # app-name
    r"(\d+|-) "  # procid ('-' for kernel)
    r"ID\d{2} "  # msgid
    r'\[expanso@32473 ip="\d{1,3}(\.\d{1,3}){3}"\] '
    r".+$"
)
RFC3164_RE = re.compile(
    r"^<\d{1,3}>"
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r"( \d|\d\d) \d{2}:\d{2}:\d{2} "  # day is space-padded to width 2
    r"[a-z0-9][a-z0-9.-]* "  # hostname
    r"[A-Za-z0-9/._-]+(\[\d+\])?: "  # TAG[pid]: ('kernel:' has no pid)
    r".+$"
)
KNOWN_FACILITIES = {0, 2, 3, 4, 9, 10, 23}


def _pri(line: str) -> int:
    match = re.match(r"<(\d+)>", line)
    assert match, line
    return int(match.group(1))


def _host(line: str) -> str:
    return line.split()[2]  # <PRI>VER TIMESTAMP HOST ... (RFC 5424)


class TestFormats:
    def test_rfc5424_lines_full_match(self) -> None:
        for line in generate(main, count=400):
            assert RFC5424_RE.match(line), line

    def test_rfc3164_lines_full_match(self) -> None:
        for line in generate(main, count=400, extra=["--rfc", "3164"]):
            assert RFC3164_RE.match(line), line

    def test_pri_in_valid_range_and_known_facilities(self) -> None:
        facilities = set()
        for line in generate(main, count=500):
            prival = _pri(line)
            assert 0 <= prival <= 191
            facilities.add(prival // 8)
        assert facilities <= KNOWN_FACILITIES
        assert len(facilities) >= 4  # a real fleet emits from many facilities

    def test_rfc5424_sd_id_is_private_expanso_not_iana_origin(self) -> None:
        # 'origin' is an IANA-registered SD-ID (RFC 5424 sec 7.2); our custom
        # ip="..." param belongs under a private enterprise SD-ID instead.
        for line in generate(main, count=300):
            assert "[expanso@32473 ip=" in line, line
            assert "origin@32473" not in line, line

    def test_rfc3164_single_digit_day_is_space_padded(self) -> None:
        lines = generate(
            main,
            count=200,
            extra=["--rfc", "3164", "--start-time", "2026-01-05T00:00:00+00:00"],
        )
        for line in lines:
            assert RFC3164_RE.match(line), line
            assert "Jan  5 " in line, line  # 'Jan  5', never 'Jan 05' or 'Jan 5'


class TestDeterminism:
    def test_same_seed_same_output(self) -> None:
        assert generate(main, count=50) == generate(main, count=50)

    def test_same_seed_same_output_3164(self) -> None:
        extra = ["--rfc", "3164"]
        assert generate(main, count=50, extra=extra) == generate(main, count=50, extra=extra)

    def test_different_seed_differs(self) -> None:
        assert generate(main, count=50, seed=1) != generate(main, count=50, seed=2)


class TestRealism:
    def test_severity_mix_mostly_info(self) -> None:
        severities = Counter(_pri(line) % 8 for line in generate(main, count=1000))
        total = sum(severities.values())
        assert severities[6] / total > 0.6  # info-heavy
        assert (severities[0] + severities[1] + severities[2]) / total < 0.03  # crit & worse rare

    def test_hosts_recur_from_small_pool(self) -> None:
        hosts = Counter(_host(line) for line in generate(main, count=600))
        assert len(hosts) <= 10
        assert hosts.most_common(1)[0][1] > 60  # skewed popularity, not uniform

    def test_paired_events_present(self) -> None:
        text = "\n".join(generate(main, count=1500))
        assert "session opened for user" in text
        assert "session closed for user" in text
        assert "connect from" in text
        assert "disconnect from" in text

    def test_port_numbers_in_valid_range(self) -> None:
        seen = 0
        for line in generate(main, count=500):
            for match in re.finditer(r" port (\d+)", line):
                seen += 1
                assert 1 <= int(match.group(1)) <= 65535
        assert seen > 50  # sshd traffic dominates, so ports must show up often


class TestScenario:
    @staticmethod
    def _failed(extra: list[str]) -> tuple[list[str], int]:
        lines = generate(main, count=900, backfill="2h", extra=extra)
        return [line for line in lines if "Failed password" in line], len(lines)

    def test_auth_burst_floods_failed_passwords(self) -> None:
        base_failed, base_total = self._failed([])
        burst_failed, burst_total = self._failed(["--scenario", "auth-burst"])
        base_rate = len(base_failed) / base_total
        burst_rate = len(burst_failed) / burst_total
        assert base_rate < 0.06
        assert burst_rate > base_rate * 2

    def test_auth_burst_targets_one_host_from_few_ips(self) -> None:
        failed, _ = self._failed(["--scenario", "auth-burst"])
        hosts = Counter(_host(line) for line in failed)
        top_host, top_count = hosts.most_common(1)[0]
        assert top_count / len(failed) > 0.6  # ONE victim host dominates
        attacker_ips = {
            match.group(1)
            for line in failed
            if _host(line) == top_host
            and (match := re.search(r"from (\d{1,3}(?:\.\d{1,3}){3}) port", line))
        }
        assert 1 <= len(attacker_ips) <= 8  # small attacker set, not random noise
