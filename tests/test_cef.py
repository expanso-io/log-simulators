"""Tests for logsim-cef (CEF / LEEF security events)."""

from __future__ import annotations

import re
from collections import Counter

from log_simulators.cef.cli import ext_escape, header_escape, main

from .conftest import generate

SIG_IDS = {"100", "101", "200", "300", "301", "400", "401"}
UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SYSLOG_PREFIX_RE = re.compile(r"^[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} edge-\d{2} CEF:0\|")
DEVTIME_RE = re.compile(r"^[A-Z][a-z]{2} \d{2} \d{4} \d{2}:\d{2}:\d{2}$")
EXT_KEY_RE = re.compile(r"(?:(?<= )|^)([A-Za-z0-9]+)=")

REQUIRED_CEF_KEYS = {
    "src",
    "spt",
    "dst",
    "dpt",
    "proto",
    "act",
    "app",
    "cs1Label",
    "cs1",
    "cn1Label",
    "cn1",
    "msg",
}
REQUIRED_LEEF_KEYS = {
    "devTime",
    "src",
    "dst",
    "srcPort",
    "dstPort",
    "proto",
    "usrName",
    "action",
    "sev",
}


def split_cef(line: str) -> list[str]:
    """Split the 7 header pipes (unescaped); part 8 is the extension string.

    Only header fields escape pipes, so the split is bounded at 7: any
    further unescaped pipes belong to extension values and stay in part 8.
    """
    return UNESCAPED_PIPE.split(line, maxsplit=7)


def parse_extensions(ext: str) -> dict[str, str]:
    """Parse CEF extensions; unambiguous because '=' in values is escaped."""
    matches = list(EXT_KEY_RE.finditer(ext))
    out: dict[str, str] = {}
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(ext)
        out[m.group(1)] = ext[m.end() : end].strip()
    return out


def parse_leef(line: str) -> tuple[list[str], dict[str, str]]:
    head = line.split("|", 5)
    attrs = dict(kv.split("=", 1) for kv in head[5].split("\t"))
    return head, attrs


class TestCEFFormat:
    def test_header_has_seven_pipes_and_intact_fields(self) -> None:
        for line in generate(main, count=300):
            parts = split_cef(line)
            assert len(parts) == 8, line
            assert parts[0] == "CEF:0"
            assert parts[1] == "Expanso"
            assert parts[2] == "EdgeGuard"
            assert parts[3] == "2.4.1"
            assert parts[4] in SIG_IDS
            assert parts[5]
            assert parts[6].isdigit() and 0 <= int(parts[6]) <= 10

    def test_extensions_parse_into_valid_fields(self) -> None:
        for line in generate(main, count=300):
            ext = parse_extensions(split_cef(line)[7])
            assert ext.keys() >= REQUIRED_CEF_KEYS, line
            assert IP_RE.match(ext["src"]) and IP_RE.match(ext["dst"])
            assert 1 <= int(ext["spt"]) <= 65535
            assert 1 <= int(ext["dpt"]) <= 65535
            assert ext["proto"] in {"TCP", "UDP"}
            assert ext["act"] in {"allowed", "blocked"}
            assert ext["cs1Label"] == "Rule"
            assert ext["cn1Label"] == "ThreatScore"
            assert 1 <= int(ext["cn1"]) <= 100

    def test_syslog_header_prefix(self) -> None:
        for line in generate(main, count=100, extra=["--syslog-header"]):
            assert SYSLOG_PREFIX_RE.match(line), line

    def test_escape_rules_differ_between_header_and_extensions(self) -> None:
        # header fields: backslash and pipe are escaped; '=' passes through
        assert header_escape("zone lan|wan") == "zone lan\\|wan"
        assert header_escape("C:\\tmp") == "C:\\\\tmp"
        assert header_escape("k=v") == "k=v"
        # extension values: backslash, '=' and newlines are escaped - never pipes
        assert ext_escape("k=v") == "k\\=v"
        assert ext_escape("C:\\tmp") == "C:\\\\tmp"
        assert ext_escape("line1\nline2") == "line1\\nline2"
        assert ext_escape("line1\rline2") == "line1\\rline2"
        assert ext_escape("zone lan|wan") == "zone lan|wan"

    def test_pipes_unescaped_in_extension_values(self) -> None:
        lines = generate(main, count=600)
        piped = [line for line in lines if "|" in split_cef(line)[7]]
        assert piped, "expected msg values containing literal pipes"
        for line in piped:
            ext_str = split_cef(line)[7]
            assert "\\|" not in ext_str, line
            msg = parse_extensions(ext_str)["msg"]
            assert "|" in msg and "\\|" not in msg, line
        # extension pipes never bleed into the 7-pipe header structure
        for line in lines:
            parts = split_cef(line)
            assert len(parts) == 8, line
            assert parts[0] == "CEF:0"
            assert parts[4] in SIG_IDS

    def test_backslash_escaping_in_file_names(self) -> None:
        lines = generate(main, count=600, backfill="2h", extra=["--scenario", "malware-burst"])
        malware = [line for line in lines if split_cef(line)[4] == "300"]
        assert malware
        windows = [line for line in malware if "\\\\" in line]
        assert windows, "expected Windows fileName backslashes to be escaped"
        for line in windows:
            ext = parse_extensions(split_cef(line)[7])
            assert "\\\\" in ext["fileName"], line


class TestLEEF:
    def test_leef_structure_and_required_attrs(self) -> None:
        for line in generate(main, count=200, extra=["--format", "leef"]):
            assert line.startswith("LEEF:2.0|Expanso|EdgeGuard|2.4.1|"), line
            head, attrs = parse_leef(line)
            assert len(head) == 6
            assert head[4] in SIG_IDS
            assert "\t" in line
            assert attrs.keys() >= REQUIRED_LEEF_KEYS, line
            assert DEVTIME_RE.match(attrs["devTime"])
            assert IP_RE.match(attrs["src"]) and IP_RE.match(attrs["dst"])
            assert 1 <= int(attrs["srcPort"]) <= 65535
            assert 1 <= int(attrs["dstPort"]) <= 65535
            assert attrs["action"] in {"allowed", "blocked"}
            assert 0 <= int(attrs["sev"]) <= 10


class TestDeterminism:
    def test_same_seed_same_output(self) -> None:
        assert generate(main, count=50) == generate(main, count=50)

    def test_same_seed_same_output_leef(self) -> None:
        extra = ["--format", "leef"]
        assert generate(main, count=50, extra=extra) == generate(main, count=50, extra=extra)

    def test_different_seed_differs(self) -> None:
        assert generate(main, count=50, seed=1) != generate(main, count=50, seed=2)


class TestRealism:
    def test_severity_info_heavy_with_rare_high(self) -> None:
        sevs = [int(split_cef(line)[6]) for line in generate(main, count=1000)]
        low = sum(s <= 3 for s in sevs) / len(sevs)
        high = sum(s >= 7 for s in sevs) / len(sevs)
        assert low > 0.55
        assert 0 < high < 0.15

    def test_entity_consistency_sources_recur(self) -> None:
        srcs = Counter(
            parse_extensions(split_cef(line)[7])["src"] for line in generate(main, count=500)
        )
        assert srcs.most_common(1)[0][1] > 10

    def test_malware_events_carry_sha256_and_filename(self) -> None:
        lines = generate(main, count=600, backfill="2h", extra=["--scenario", "malware-burst"])
        malware = [line for line in lines if split_cef(line)[4] == "300"]
        assert malware
        for line in malware:
            ext = parse_extensions(split_cef(line)[7])
            assert SHA256_RE.match(ext["fileHash"]), line
            assert ext["fileName"]


class TestScenario:
    def test_malware_burst_raises_high_sev_rate(self) -> None:
        def high_rate(extra: list[str]) -> float:
            lines = generate(main, count=800, backfill="2h", extra=extra)
            sevs = [int(split_cef(line)[6]) for line in lines]
            return sum(s >= 9 for s in sevs) / len(sevs)

        baseline = high_rate([])
        burst = high_rate(["--scenario", "malware-burst"])
        assert baseline < 0.05
        assert burst > baseline * 3
        assert burst > 0.05

    def test_burst_shares_infected_host_and_hash_set(self) -> None:
        lines = generate(main, count=800, backfill="2h", extra=["--scenario", "malware-burst"])
        hot = [
            parse_extensions(split_cef(line)[7]) for line in lines if int(split_cef(line)[6]) >= 9
        ]
        assert len(hot) > 20
        srcs = Counter(event["src"] for event in hot)
        assert srcs.most_common(1)[0][1] / len(hot) > 0.5
        hashes = Counter(event["fileHash"] for event in hot if "fileHash" in event)
        assert hashes and hashes.most_common(1)[0][1] > 5
        # only the small burst hash set repeats; baseline hashes are one-offs
        assert len([h for h, c in hashes.items() if c > 1]) <= 3
