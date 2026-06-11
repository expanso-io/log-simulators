"""Tests for logsim-windows (Windows Security Event Log)."""

from __future__ import annotations

import json
import re

# stdlib ElementTree is safe here: we only parse XML this simulator just
# generated in-process (trusted input, no DTDs/external entities), and the
# project is stdlib+faker only by design.
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from itertools import pairwise

from log_simulators.windows.cli import main

from .conftest import generate

XMLNS = "http://schemas.microsoft.com/win/2004/08/events/event"
NS = {"e": XMLNS}
ALLOWED_IDS = {4624, 4625, 4672, 4688, 4720, 4740}
SINGLE_LINE_RE = re.compile(
    r'^<Event xmlns="http://schemas\.microsoft\.com/win/2004/08/events/event">'
    r"<System>.+</System><EventData>.+</EventData></Event>$"
)
# Real events render FILETIME at 100-ns resolution: 7 fractional digits.
SYSTIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$")
DOMAIN_SID_RE = re.compile(r"^S-1-5-21-\d+-\d+-\d+-\d+$")
GUID_RE = re.compile(r"^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$")
NULL_GUID = "{00000000-0000-0000-0000-000000000000}"
HEX_PID_RE = re.compile(r"^0x[0-9a-f]+$")

# Version-2 manifest fields that v0/v1 events lack (4624 and 4688).
V2_4624_FIELDS = {
    "LogonGuid",
    "TransmittedServices",
    "LmPackageName",
    "KeyLength",
    "ProcessId",
    "ImpersonationLevel",
    "RestrictedAdminMode",
    "TargetOutboundUserName",
    "TargetOutboundDomainName",
    "VirtualAccount",
    "TargetLinkedLogonId",
    "ElevatedToken",
}
V2_4688_FIELDS = {
    "TargetUserSid",
    "TargetUserName",
    "TargetDomainName",
    "TargetLogonId",
    "MandatoryLabel",
}


def _parse(line: str) -> ET.Element:
    root = ET.fromstring(line)
    assert root.tag == f"{{{XMLNS}}}Event"
    return root


def _event_id(root: ET.Element) -> int:
    return int(root.findtext("e:System/e:EventID", namespaces=NS) or 0)


def _event_data(root: ET.Element) -> dict[str, str]:
    return {d.get("Name") or "": d.text or "" for d in root.findall("e:EventData/e:Data", NS)}


def _events_from_pretty(lines: list[str]) -> list[str]:
    events: list[str] = []
    buf: list[str] = []
    for line in lines:
        buf.append(line)
        if line == "</Event>":
            events.append("\n".join(buf))
            buf = []
    assert not buf, "trailing partial event"
    return events


def _records(count: int = 400, extra: list[str] | None = None, **kw: object) -> list[dict]:
    lines = generate(main, count=count, extra=["--format", "ndjson", *(extra or [])], **kw)  # type: ignore[arg-type]
    return [json.loads(line) for line in lines]


class TestXmlFormat:
    def test_every_line_is_a_valid_single_line_event(self) -> None:
        for line in generate(main, count=300):
            assert SINGLE_LINE_RE.match(line), line
            root = _parse(line)
            event_id = int(root.findtext("e:System/e:EventID", namespaces=NS) or 0)
            assert event_id in ALLOWED_IDS
            systime = root.find("e:System/e:TimeCreated", NS)
            assert systime is not None and SYSTIME_RE.match(systime.get("SystemTime", ""))
            provider = root.find("e:System/e:Provider", NS)
            assert provider is not None
            assert provider.get("Name") == "Microsoft-Windows-Security-Auditing"
            assert root.findtext("e:System/e:Channel", namespaces=NS) == "Security"
            computer = root.findtext("e:System/e:Computer", namespaces=NS) or ""
            assert computer.endswith(".CORP.EXAMPLE.COM")
            assert root.findall("e:EventData/e:Data", NS), "EventData must not be empty"

    def test_record_ids_increase_per_computer_not_globally(self) -> None:
        # Each machine keeps its own Security log: EventRecordID must be
        # strictly increasing (and gapless) per Computer, while the merged
        # stream must NOT look like one shared global counter.
        by_computer: defaultdict[str, list[int]] = defaultdict(list)
        merged: list[int] = []
        for line in generate(main, count=400):
            root = _parse(line)
            computer = root.findtext("e:System/e:Computer", namespaces=NS) or ""
            rid = int(root.findtext("e:System/e:EventRecordID", namespaces=NS) or 0)
            by_computer[computer].append(rid)
            merged.append(rid)
        assert len(by_computer) >= 3, "expected events from several computers"
        for computer, ids in by_computer.items():
            assert all(b == a + 1 for a, b in pairwise(ids)), computer
        bases = {ids[0] for ids in by_computer.values()}
        assert len(bases) == len(by_computer), "per-computer counter bases must be distinct"
        assert not all(b > a for a, b in pairwise(merged)), "global gapless counter is unrealistic"

    def test_failed_logons_use_failure_keywords(self) -> None:
        seen = set()
        for line in generate(main, count=600):
            root = _parse(line)
            event_id = int(root.findtext("e:System/e:EventID", namespaces=NS) or 0)
            keywords = root.findtext("e:System/e:Keywords", namespaces=NS)
            expected = "0x8010000000000000" if event_id == 4625 else "0x8020000000000000"
            assert keywords == expected
            seen.add(event_id)
        assert 4625 in seen

    def test_pretty_emits_parseable_multiline_events(self) -> None:
        lines = generate(main, count=60, extra=["--pretty"])
        events = _events_from_pretty(lines)
        assert len(events) == 60
        for event in events:
            assert "\n" in event
            _parse(event)

    def test_event_mix_is_logon_heavy(self) -> None:
        counts: Counter[int] = Counter()
        for line in generate(main, count=800):
            root = _parse(line)
            counts[int(root.findtext("e:System/e:EventID", namespaces=NS) or 0)] += 1
        assert counts[4624] > 0.4 * 800
        assert counts[4688] > 0.15 * 800
        assert counts[4672] > 0  # paired follow-ups to admin logons


class TestManifestV2:
    def test_4624_emits_full_version2_field_set(self) -> None:
        seen = 0
        for line in generate(main, count=600):
            root = _parse(line)
            if _event_id(root) != 4624:
                continue
            seen += 1
            assert root.findtext("e:System/e:Version", namespaces=NS) == "2"
            data = _event_data(root)
            assert data.keys() >= V2_4624_FIELDS, V2_4624_FIELDS - data.keys()
            assert GUID_RE.match(data["LogonGuid"])
            assert data["TransmittedServices"] == "-"
            assert data["ImpersonationLevel"] == "%%1833"
            assert data["RestrictedAdminMode"] == "-"
            assert data["TargetOutboundUserName"] == "-"
            assert data["TargetOutboundDomainName"] == "-"
            assert data["VirtualAccount"] == "%%1843"
            assert data["TargetLinkedLogonId"] == "0x0"
            assert data["ElevatedToken"] in {"%%1842", "%%1843"}
            # correlations: LM/key length follow the auth package, LogonGuid
            # is real for Kerberos and the null GUID otherwise, ProcessId is
            # 0x0 exactly when ProcessName is '-' (network logons)
            if data["AuthenticationPackageName"] == "NTLM":
                assert data["LmPackageName"] == "NTLM V2"
                assert data["KeyLength"] == "128"
            else:
                assert data["LmPackageName"] == "-"
                assert data["KeyLength"] == "0"
            if data["AuthenticationPackageName"] == "Kerberos":
                assert data["LogonGuid"] != NULL_GUID
            else:
                assert data["LogonGuid"] == NULL_GUID
            assert HEX_PID_RE.match(data["ProcessId"])
            assert (data["ProcessId"] == "0x0") == (data["ProcessName"] == "-")
        assert seen > 100

    def test_4688_emits_version2_target_and_label_fields(self) -> None:
        seen = 0
        for line in generate(main, count=600):
            root = _parse(line)
            if _event_id(root) != 4688:
                continue
            seen += 1
            assert root.findtext("e:System/e:Version", namespaces=NS) == "2"
            data = _event_data(root)
            assert data.keys() >= V2_4688_FIELDS, V2_4688_FIELDS - data.keys()
            assert data["TargetUserSid"] == "S-1-0-0"
            assert data["TargetUserName"] == "-"
            assert data["TargetDomainName"] == "-"
            assert data["TargetLogonId"] == "0x0"
            assert data["MandatoryLabel"] in {"S-1-16-8192", "S-1-16-12288"}
        assert seen > 50

    def test_elevated_token_and_mandatory_label_correlate_with_admins(self) -> None:
        records = _records(count=800)
        # admins are exactly the users who earn paired 4672 events
        admins = {r["subject_user"] for r in records if r["event_id"] == 4672}
        assert admins
        logons = [r for r in records if r["event_id"] == 4624]
        # the final record may be an admin 4624 whose paired 4672 was cut off
        for rec in logons[:-1]:
            expected = "%%1842" if rec["target_user"] in admins else "%%1843"
            assert rec["elevated_token"] == expected, rec["target_user"]
        assert any(r["elevated_token"] == "%%1842" for r in logons)
        procs = [r for r in records if r["event_id"] == 4688]
        assert procs
        for rec in procs:
            if rec["subject_user"] in admins:
                assert rec["mandatory_label"] == "S-1-16-12288"
            else:
                assert rec["mandatory_label"] == "S-1-16-8192"
        assert any(r["mandatory_label"] == "S-1-16-12288" for r in procs)


class TestNdjsonFormat:
    def test_every_line_parses_with_required_keys(self) -> None:
        for rec in _records(count=300):
            assert {"@timestamp", "event_id", "computer", "record_id"} <= rec.keys()
            assert rec["event_id"] in ALLOWED_IDS
            assert rec["computer"].endswith(".CORP.EXAMPLE.COM")

    def test_4624_fields(self) -> None:
        logons = [r for r in _records(count=500) if r["event_id"] == 4624]
        assert logons
        for rec in logons:
            assert rec["logon_type"] in {2, 3, 5, 10}
            assert rec["target_user"]
            assert rec["auth_package"] in {"Kerberos", "NTLM", "Negotiate"}
            # 4624's ProcessId is the logon process, never a parent pid
            assert HEX_PID_RE.match(rec["process_id"])
            assert "parent_process_id" not in rec
            assert rec["elevated_token"] in {"%%1842", "%%1843"}
            assert GUID_RE.match(rec["logon_guid"])
            if rec["logon_type"] in {3, 10}:
                assert rec["source_ip"].startswith("10.0.")
                assert 1024 <= rec["source_port"] <= 65535


class TestDeterminism:
    def test_same_seed_same_output(self) -> None:
        assert generate(main, count=50) == generate(main, count=50)

    def test_different_seed_differs(self) -> None:
        assert generate(main, count=50, seed=1) != generate(main, count=50, seed=2)


class TestRealism:
    def test_sid_is_stable_per_user(self) -> None:
        sid_by_user: defaultdict[str, set[str]] = defaultdict(set)
        for rec in _records(count=800):
            if rec["event_id"] == 4624:
                sid_by_user[rec["target_user"]].add(rec["target_sid"])
        assert sid_by_user
        for user, sids in sid_by_user.items():
            assert len(sids) == 1, f"{user} has multiple SIDs: {sids}"
            assert DOMAIN_SID_RE.match(next(iter(sids)))

    def test_users_recur(self) -> None:
        users = Counter(r["target_user"] for r in _records(count=500) if r["event_id"] == 4624)
        assert users.most_common(1)[0][1] > 5
        assert len(users) <= 20

    def test_4672_immediately_follows_matching_admin_4624(self) -> None:
        records = _records(count=600)
        special = [i for i, r in enumerate(records) if r["event_id"] == 4672]
        assert special, "expected paired 4672 events in a 600-event sample"
        for i in special:
            prev = records[i - 1]
            assert prev["event_id"] == 4624
            assert prev["target_user"] == records[i]["subject_user"]
            assert prev["logon_id"] == records[i]["subject_logon_id"]
            assert records[i]["privileges"].startswith("Se")

    def test_4688_command_line_matches_image(self) -> None:
        procs = [r for r in _records(count=600) if r["event_id"] == 4688]
        assert procs
        for rec in procs:
            assert rec["process"].lower().endswith(".exe")
            basename = rec["process"].rsplit("\\", 1)[-1].lower()
            assert basename in rec["command_line"].lower()
            assert rec["parent_process"].lower().endswith(".exe")


class TestScenario:
    def test_brute_force_raises_4625_fraction(self) -> None:
        def frac_4625(extra: list[str]) -> float:
            records = _records(count=800, backfill="2h", extra=extra)
            return sum(r["event_id"] == 4625 for r in records) / len(records)

        baseline = frac_4625([])
        attack = frac_4625(["--scenario", "brute-force"])
        assert baseline < 0.10
        assert attack > baseline * 2

    def test_brute_force_flood_shape_and_breach(self) -> None:
        records = _records(count=800, backfill="2h", extra=["--scenario", "brute-force"])
        failures = [r for r in records if r["event_id"] == 4625]
        attacker_ip = Counter(r.get("source_ip", "-") for r in failures).most_common(1)[0][0]
        flood = [r for r in failures if r.get("source_ip") == attacker_ip]
        # one IP, many usernames, NTLM type-3 with the canonical NT status codes
        assert len(flood) > 50
        assert len({r["target_user"] for r in flood}) > 8
        assert all(r["logon_type"] == 3 for r in flood)
        assert all(r["status"] == "0xC000006D" for r in flood)
        assert all(r["sub_status"] == "0xC000006A" for r in flood)
        # nonexistent accounts are being sprayed too
        legit = {r["target_user"] for r in records if r["event_id"] == 4624}
        assert {r["target_user"] for r in flood} - legit
        # the breach: a single 4624 success from the attacker IP at window end
        breaches = [
            r for r in records if r["event_id"] == 4624 and r.get("source_ip") == attacker_ip
        ]
        assert len(breaches) == 1
        # lockouts get sprinkled into the flood
        assert any(r["event_id"] == 4740 for r in records)
