"""Tests for logsim-asa (Cisco ASA firewall syslog)."""

from __future__ import annotations

import re
from collections import Counter
from itertools import pairwise

from log_simulators.asa.cli import main

from .conftest import generate

IP = r"(?:\d{1,3}\.){3}\d{1,3}"

BUILD_RE = re.compile(
    rf"^%ASA-6-(302013|302015): Built outbound (TCP|UDP) connection (\d+) for "
    rf"outside:{IP}/\d+ \({IP}/\d+\) to inside:{IP}/\d+ \({IP}/\d+\)$"
)
TEARDOWN_TCP_RE = re.compile(
    rf"^%ASA-6-302014: Teardown TCP connection (\d+) for outside:{IP}/\d+ to "
    rf"inside:{IP}/\d+ duration (\d+:\d{{2}}:\d{{2}}) bytes \d+ "
    rf"(TCP FINs|TCP Reset-I|TCP Reset-O|SYN Timeout|Idle Timeout)$"
)
TEARDOWN_UDP_RE = re.compile(
    rf"^%ASA-6-302016: Teardown UDP connection (\d+) for outside:{IP}/\d+ to "
    rf"inside:{IP}/\d+ duration (\d+:\d{{2}}:\d{{2}}) bytes \d+$"
)
DENY_RE = re.compile(
    rf"^%ASA-4-106023: Deny (tcp|udp) src outside:({IP})/\d+ dst inside:({IP})/(\d+) "
    rf'by access-group "[A-Z_]+" \[0x0, 0x0\]$'
)
XLATE_RE = re.compile(
    rf"^%ASA-6-305011: Built dynamic (TCP|UDP) translation from inside:{IP}/(\d+) "
    rf"to outside:{IP}/(\d+)$"
)
LOGIN_RE = re.compile(
    rf'^%ASA-6-605005: Login permitted from {IP}/\d+ to inside:{IP}/ssh for user "[^"]+"$'
)
AAA_RE = re.compile(
    rf"^%ASA-4-113019: Group = \S+, Username = \S+, IP = {IP}, Session disconnected\. "
    rf"Session Type: SSL, Duration: \d+h:\d{{2}}m:\d{{2}}s, "
    rf"Bytes xmt: \d+, Bytes rcv: \d+, Reason: .+$"
)
ALL_RES = [BUILD_RE, TEARDOWN_TCP_RE, TEARDOWN_UDP_RE, DENY_RE, XLATE_RE, LOGIN_RE, AAA_RE]
SYSLOG_RE = re.compile(
    r"^<(\d{2,3})>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \S+ : (%ASA-(\d)-\d{6}: .+)$"
)
BUILD_INSIDE_RE = re.compile(rf"to inside:({IP})/\d+")


class TestFormats:
    def test_every_line_matches_a_known_message_type(self) -> None:
        for line in generate(main, count=800):
            assert any(r.match(line) for r in ALL_RES), line

    def test_build_code_matches_protocol(self) -> None:
        seen = set()
        for line in generate(main, count=800):
            m = BUILD_RE.match(line)
            if not m:
                continue
            code, proto = m.group(1), m.group(2)
            assert (code, proto) in {("302013", "TCP"), ("302015", "UDP")}, line
            seen.add(proto)
        assert seen == {"TCP", "UDP"}

    def test_syslog_header_wraps_valid_messages(self) -> None:
        for line in generate(main, count=300, extra=["--syslog-header"]):
            m = SYSLOG_RE.match(line)
            assert m, line
            assert any(r.match(m.group(2)) for r in ALL_RES), line
            # PRI = facility 20 (local4) * 8 + severity from the %ASA tag
            assert int(m.group(1)) == 160 + int(m.group(3)), line

    def test_113019_is_severity_4_and_pri_follows(self) -> None:
        # Real ASA logs VPN session disconnect as %ASA-4-113019 (warning),
        # so a header-wrapped line must carry PRI 164 (local4*8 + 4).
        vpn_lines = [
            line
            for line in generate(main, count=5000, extra=["--syslog-header"])
            if "113019" in line
        ]
        assert vpn_lines, "expected at least one 113019 event in 5000 lines"
        for line in vpn_lines:
            m = SYSLOG_RE.match(line)
            assert m, line
            assert m.group(2).startswith("%ASA-4-113019: "), line
            assert int(m.group(1)) == 164, line


class TestDeterminism:
    def test_same_seed_same_output(self) -> None:
        assert generate(main, count=120) == generate(main, count=120)

    def test_different_seed_differs(self) -> None:
        assert generate(main, count=120, seed=1) != generate(main, count=120, seed=2)


class TestConnectionPairing:
    def test_every_teardown_was_built_first_and_only_torn_down_once(self) -> None:
        open_ids: set[int] = set()
        teardowns = 0
        for line in generate(main, count=1500):
            if m := BUILD_RE.match(line):
                open_ids.add(int(m.group(3)))
            elif m := TEARDOWN_TCP_RE.match(line) or TEARDOWN_UDP_RE.match(line):
                cid = int(m.group(1))
                assert cid in open_ids, f"teardown of never-built/already-closed conn: {line}"
                open_ids.remove(cid)
                teardowns += 1
        assert teardowns > 100

    def test_build_conn_ids_strictly_increasing(self) -> None:
        ids = [int(m.group(3)) for line in generate(main, count=800) if (m := BUILD_RE.match(line))]
        assert len(ids) > 100
        assert all(b > a for a, b in pairwise(ids))

    def test_teardown_duration_format(self) -> None:
        durations = []
        for line in generate(main, count=1000):
            m = TEARDOWN_TCP_RE.match(line) or TEARDOWN_UDP_RE.match(line)
            if m:
                durations.append(m.group(2))
        assert durations
        for dur in durations:
            assert re.fullmatch(r"\d+:\d{2}:\d{2}", dur), dur


class TestRealism:
    def test_inside_hosts_recur(self) -> None:
        hosts = Counter(
            m.group(1)
            for line in generate(main, count=600)
            if BUILD_RE.match(line) and (m := BUILD_INSIDE_RE.search(line))
        )
        assert hosts and hosts.most_common(1)[0][1] > 5

    def test_tcp_heavy_protocol_mix(self) -> None:
        protos = Counter(
            m.group(2) for line in generate(main, count=1000) if (m := BUILD_RE.match(line))
        )
        total = protos["TCP"] + protos["UDP"]
        assert 0.55 < protos["TCP"] / total < 0.92

    def test_https_dominates_tcp_destination_ports(self) -> None:
        ports = Counter(
            line.split(" for outside:")[1].split(" ")[0].split("/")[1]
            for line in generate(main, count=1000)
            if line.startswith("%ASA-6-302013")
        )
        assert ports.most_common(1)[0][0] == "443"

    def test_mgmt_garnish_is_rare_but_present(self) -> None:
        lines = generate(main, count=3000)
        mgmt = [line for line in lines if LOGIN_RE.match(line) or AAA_RE.match(line)]
        assert 0 < len(mgmt) / len(lines) < 0.05


class TestScenario:
    @staticmethod
    def _deny_fraction(extra: list[str]) -> float:
        lines = generate(main, count=800, backfill="2h", extra=extra)
        return sum(1 for line in lines if DENY_RE.match(line)) / len(lines)

    def test_port_scan_raises_deny_fraction(self) -> None:
        baseline = self._deny_fraction([])
        scan = self._deny_fraction(["--scenario", "port-scan"])
        assert baseline < 0.25
        assert scan > baseline * 2

    def test_port_scan_sweeps_sequential_ports_from_one_source(self) -> None:
        by_src: dict[str, list[int]] = {}
        for line in generate(main, count=800, backfill="2h", extra=["--scenario", "port-scan"]):
            if m := DENY_RE.match(line):
                by_src.setdefault(m.group(2), []).append(int(m.group(4)))
        scanner = max(by_src, key=lambda src: len(by_src[src]))
        ports = by_src[scanner]
        assert len(set(ports)) >= 10
        sequential_steps = sum(1 for a, b in pairwise(ports) if b - a == 1)
        assert sequential_steps >= 9
