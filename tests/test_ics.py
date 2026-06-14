"""Tests for logsim-ics (OT / ICS network-device syslog)."""

from __future__ import annotations

import re
from collections import Counter

from log_simulators.ics.cli import main

from .conftest import generate

IP = r"(?:\d{1,3}\.){3}\d{1,3}"
# %FAC-<sev>-MNEMONIC: text  - the Cisco-IOS-style message block.
BLOCK = r"%[A-Z]+-(?P<sev>\d)-[A-Z_]+: .+"

RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>1 "
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}(Z|[+-]\d{2}:\d{2}) "
    r"(?P<host>[a-z0-9][a-z0-9.-]*) "  # hostname (lowercase FQDN)
    r"NETWORK-DEVICE - - - "  # app procid msgid sd
    rf"(?P<block>{BLOCK})$"
)
RFC3164_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r"( \d|\d\d) \d{2}:\d{2}:\d{2} "  # day space-padded to width 2
    r"(?P<host>[a-z0-9][a-z0-9.-]*) "
    r"NETWORK-DEVICE: "
    rf"(?P<block>{BLOCK})$"
)
RE_FOR = {"5424": RFC5424_RE, "3164": RFC3164_RE}

PLC_IP_RE = re.compile(rf"PLC at ({IP}) over")
# %FAC-SEV-MNEMONIC: ... - pull the facility, severity digit, and mnemonic apart.
MNEMONIC_RE = re.compile(r"%(?P<fac>[A-Z]+)-(?P<sev>\d)-(?P<mnem>[A-Z_]+): ")
# "Port <id> changed state to UP|DOWN|..." inside %PORT-5-LINK_STATE_CHANGE lines.
PORT_STATE_RE = re.compile(
    r"Port (?P<port>\S+) changed state to (?P<state>UP|DOWN|BLOCKING|ERR-DISABLED)"
)


def _re(rfc: str) -> re.Pattern[str]:
    return RE_FOR[rfc]


class TestFormats:
    def test_rfc5424_lines_full_match(self) -> None:
        for line in generate(main, count=500):
            assert RFC5424_RE.fullmatch(line), line

    def test_rfc3164_lines_full_match(self) -> None:
        for line in generate(main, count=500, extra=["--rfc", "3164"]):
            assert RFC3164_RE.fullmatch(line), line

    def test_both_variants_match_under_scenario(self) -> None:
        for rfc in ("5424", "3164"):
            extra = ["--rfc", rfc, "--scenario", "plc-comm-loss"]
            for line in generate(main, count=400, backfill="2h", extra=extra):
                assert _re(rfc).fullmatch(line), line

    def test_pri_in_valid_range_and_single_facility(self) -> None:
        facilities = set()
        for line in generate(main, count=500):
            prival = int(RFC5424_RE.fullmatch(line).group("pri"))  # type: ignore[union-attr]
            assert 0 <= prival <= 191
            facilities.add(prival // 8)
        assert facilities == {23}  # local7, fixed for every line


class TestPriSeverityAgreement:
    def test_pri_severity_digit_equals_mnemonic_severity(self) -> None:
        for rfc in ("5424", "3164"):
            checked = 0
            for line in generate(main, count=800, extra=["--rfc", rfc]):
                m = _re(rfc).fullmatch(line)
                assert m, line
                # mnemonic severity digit must equal PRI % 8 on every line
                assert int(m.group("pri")) % 8 == int(m.group("sev")), line
                checked += 1
            assert checked == 800


class TestMnemonicSeverityIsFixed:
    def test_each_mnemonic_maps_to_one_severity(self) -> None:
        # Real Cisco IOS pins a (facility, mnemonic) pair to a FIXED severity,
        # so every distinct MNEMONIC string must carry exactly one severity
        # digit. Sample baseline + scenario across both wire formats and a large
        # volume so the incident path's own blocks are covered too.
        sev_by_mnem: dict[str, set[str]] = {}
        samples = (
            generate(main, count=2000)
            + generate(main, count=2000, extra=["--rfc", "3164"])
            + generate(main, count=2000, backfill="2h", extra=["--scenario", "plc-comm-loss"])
        )
        for line in samples:
            m = MNEMONIC_RE.search(line)
            assert m, line
            sev_by_mnem.setdefault(m.group("mnem"), set()).add(m.group("sev"))

        offenders = {k: v for k, v in sev_by_mnem.items() if len(v) != 1}
        assert not offenders, f"mnemonics mapping to multiple severities: {offenders}"
        # REP link-status changes (up OR down) are pinned to %REP-4-LINKSTATUS.
        assert sev_by_mnem["LINKSTATUS"] == {"4"}


class TestDeterminism:
    def test_same_seed_same_output(self) -> None:
        assert generate(main, count=80) == generate(main, count=80)

    def test_same_seed_same_output_3164(self) -> None:
        extra = ["--rfc", "3164"]
        assert generate(main, count=80, extra=extra) == generate(main, count=80, extra=extra)

    def test_different_seed_differs(self) -> None:
        assert generate(main, count=80, seed=1) != generate(main, count=80, seed=2)


class TestRfc3164Padding:
    def test_single_digit_day_is_space_padded(self) -> None:
        lines = generate(
            main,
            count=200,
            extra=["--rfc", "3164", "--start-time", "2026-01-05T00:00:00+00:00"],
        )
        for line in lines:
            assert RFC3164_RE.fullmatch(line), line
            assert "Jan  5 " in line, line  # 'Jan  5', never 'Jan 05' or 'Jan 5'


class TestRealism:
    def test_severity_mix_is_info_notice_heavy(self) -> None:
        sev = Counter(
            int(m.group("sev"))
            for line in generate(main, count=1500)
            if (m := RFC5424_RE.fullmatch(line))
        )
        total = sum(sev.values())
        assert (sev[5] + sev[6]) / total > 0.6  # notice + info dominate
        assert (sev[2] + sev[3]) / total < 0.10  # err & worse are rare

    def test_devices_recur_from_a_small_pool(self) -> None:
        hosts = Counter(
            m.group("host")
            for line in generate(main, count=800)
            if (m := RFC5424_RE.fullmatch(line))
        )
        assert len(hosts) <= 12  # 8 switches + 2 routers + 2 gateways
        assert hosts.most_common(1)[0][1] > 80  # zipf-skewed, not uniform

    def test_plc_endpoints_recur_from_stable_ot_pool(self) -> None:
        ips = [ip for line in generate(main, count=2000) for ip in PLC_IP_RE.findall(line)]
        assert len(ips) > 20
        assert all(ip.startswith("10.20.") for ip in ips)  # stable OT subnet
        assert len(set(ips)) <= 40  # bounded pool, never random
        assert Counter(ips).most_common(1)[0][1] >= 2  # a PLC recurs


class TestScenario:
    @staticmethod
    def _ind3_fraction(extra: list[str]) -> float:
        lines = generate(main, count=1200, backfill="2h", extra=extra)
        ind3 = sum(1 for line in lines if "%IND-3-PLC_COMM_LOSS:" in line)
        return ind3 / len(lines)

    def test_plc_comm_loss_raises_ind3_fraction(self) -> None:
        baseline = self._ind3_fraction([])
        scenario = self._ind3_fraction(["--scenario", "plc-comm-loss"])
        assert baseline < 0.06
        assert scenario > baseline * 2
        assert scenario > 0.04

    def test_plc_comm_loss_emits_matching_restored(self) -> None:
        lines = generate(main, count=1200, backfill="2h", extra=["--scenario", "plc-comm-loss"])

        def host_of(line: str) -> str | None:
            m = RFC5424_RE.fullmatch(line)
            return m.group("host") if m else None

        loss = [line for line in lines if "%IND-3-PLC_COMM_LOSS:" in line]
        restored = [line for line in lines if "%IND-5-PLC_COMM_RESTORED:" in line]
        assert loss, "expected comm-loss events during the scenario"
        assert restored, "expected matching PLC_COMM_RESTORED recovery events"

        # The same victim switch that loses comms is the one that recovers.
        victim = Counter(host_of(line) for line in loss).most_common(1)[0][0]
        assert Counter(host_of(line) for line in restored).most_common(1)[0][0] == victim

        # Recovery names PLCs that went down on that victim segment.
        loss_plcs = {
            ip for line in loss if host_of(line) == victim for ip in PLC_IP_RE.findall(line)
        }
        restored_plcs = {
            ip for line in restored if host_of(line) == victim for ip in PLC_IP_RE.findall(line)
        }
        assert restored_plcs & loss_plcs

    def test_plc_comm_loss_recovers_downed_victim_port(self) -> None:
        lines = generate(main, count=2400, backfill="2h", extra=["--scenario", "plc-comm-loss"])

        def host_of(line: str) -> str | None:
            m = RFC5424_RE.fullmatch(line)
            return m.group("host") if m else None

        loss = [line for line in lines if "%IND-3-PLC_COMM_LOSS:" in line]
        assert loss, "expected comm-loss events during the scenario"
        victim = Counter(host_of(line) for line in loss).most_common(1)[0][0]

        # Track which ports the victim switch drove DOWN vs brought back UP.
        down_ports: set[str] = set()
        up_ports: set[str] = set()
        for line in lines:
            if host_of(line) != victim or "%PORT-5-LINK_STATE_CHANGE:" not in line:
                continue
            m = PORT_STATE_RE.search(line)
            if not m:
                continue
            if m.group("state") == "DOWN":
                down_ports.add(m.group("port"))
            elif m.group("state") == "UP":
                up_ports.add(m.group("port"))

        assert down_ports, "victim port should flap DOWN during the loss phase"
        # The recovery tail must bring the SAME downed victim port back UP, not
        # leave the physical link dead while only PLC comms 'recover'.
        assert down_ports & up_ports, "recovery tail must return the downed victim port to UP"

    def test_plc_comm_loss_recovery_restores_ring_segment(self) -> None:
        # The victim ring segment that fails (%REP-4-LINKSTATUS ...FAILED) must
        # also be returned to normal (...UP) on the same victim switch.
        lines = generate(main, count=2400, backfill="2h", extra=["--scenario", "plc-comm-loss"])

        def host_of(line: str) -> str | None:
            m = RFC5424_RE.fullmatch(line)
            return m.group("host") if m else None

        loss = [line for line in lines if "%IND-3-PLC_COMM_LOSS:" in line]
        assert loss
        victim = Counter(host_of(line) for line in loss).most_common(1)[0][0]

        rep = [line for line in lines if host_of(line) == victim and "%REP-4-LINKSTATUS:" in line]
        failed = [line for line in rep if "link status FAILED" in line]
        recovered = [line for line in rep if "link status UP" in line]
        assert failed, "victim ring segment should report FAILED during the loss phase"
        assert recovered, "recovery tail must return the victim ring segment to UP"

    def test_plc_comm_loss_targets_one_switch(self) -> None:
        lines = generate(main, count=1200, backfill="2h", extra=["--scenario", "plc-comm-loss"])
        hosts = Counter(
            m.group("host")
            for line in lines
            if "%IND-3-PLC_COMM_LOSS:" in line and (m := RFC5424_RE.fullmatch(line))
        )
        # One victim switch owns the comm-loss wave.
        assert hosts.most_common(1)[0][1] / sum(hosts.values()) > 0.6
        assert hosts.most_common(1)[0][0].startswith("cell")
