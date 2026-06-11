"""Tests for logsim-cloud (AWS CloudTrail records and VPC Flow Logs)."""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from log_simulators.cloud.cli import main

from .conftest import generate

EVENT_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
PRINCIPAL_RE = re.compile(r"^AIDA[A-Z2-7]{17}$")
ENI_RE = re.compile(r"^eni-0[0-9a-f]{16}$")
UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
S3_REQUEST_ID_RE = re.compile(r"^[0-9A-F]{16,17}$")
S3_DATA_EVENTS = ("GetObject", "PutObject")
REQUIRED_KEYS = {
    "eventVersion",
    "userIdentity",
    "eventTime",
    "eventSource",
    "eventName",
    "awsRegion",
    "sourceIPAddress",
    "userAgent",
    "requestParameters",
    "responseElements",
    "requestID",
    "eventID",
    "eventType",
    "recipientAccountId",
    "eventCategory",
    "managementEvent",
}


def _records(count: int = 300, extra: list[str] | None = None, **kw: Any) -> list[dict[str, Any]]:
    return [json.loads(line) for line in generate(main, count=count, extra=extra, **kw)]


class TestCloudTrailFormat:
    def test_records_parse_with_required_keys(self) -> None:
        records = _records(300)
        assert records
        for rec in records:
            assert rec.keys() >= REQUIRED_KEYS, rec
            assert rec["eventVersion"] == "1.08"
            assert EVENT_TIME_RE.match(rec["eventTime"]), rec["eventTime"]
            assert IPV4_RE.match(rec["sourceIPAddress"]), rec["sourceIPAddress"]
            assert rec["eventSource"].endswith(".amazonaws.com")
            uuid_parts = rec["eventID"].split("-")
            assert [len(p) for p in uuid_parts] == [8, 4, 4, 4, 12]

    def test_username_keeps_stable_principal_id(self) -> None:
        seen: dict[str, str] = {}
        for rec in _records(600):
            ident = rec["userIdentity"]
            if ident["type"] != "IAMUser":
                continue
            assert PRINCIPAL_RE.match(ident["principalId"]), ident
            assert ident["arn"].endswith(f"user/{ident['userName']}")
            prior = seen.setdefault(ident["userName"], ident["principalId"])
            assert prior == ident["principalId"]
        assert len(seen) > 3

    def test_console_login_shape(self) -> None:
        logins = [r for r in _records(1500) if r["eventName"] == "ConsoleLogin"]
        assert logins
        for rec in logins:
            assert rec["eventSource"] == "signin.amazonaws.com"
            assert rec["eventType"] == "AwsConsoleSignIn"
            assert rec["responseElements"]["ConsoleLogin"] in ("Success", "Failure")

    def test_every_record_has_category_and_management_flag(self) -> None:
        records = _records(600)
        categories = {r["eventCategory"] for r in records}
        assert categories == {"Management", "Data"}
        for rec in records:
            assert isinstance(rec["managementEvent"], bool), rec
            assert (rec["eventCategory"] == "Management") == rec["managementEvent"], rec

    def test_s3_data_events_have_category_and_resources(self) -> None:
        records = _records(600)
        s3 = [r for r in records if r["eventName"] in S3_DATA_EVENTS]
        assert s3
        for rec in s3:
            assert rec["eventCategory"] == "Data"
            assert rec["managementEvent"] is False
            bucket = rec["requestParameters"]["bucketName"]
            key = rec["requestParameters"]["key"]
            obj_res, bucket_res = rec["resources"]
            assert obj_res == {
                "type": "AWS::S3::Object",
                "ARN": f"arn:aws:s3:::{bucket}/{key}",
            }
            assert bucket_res == {
                "accountId": rec["recipientAccountId"],
                "type": "AWS::S3::Bucket",
                "ARN": f"arn:aws:s3:::{bucket}",
            }

    def test_non_s3_records_are_management_without_resources(self) -> None:
        records = _records(600)
        other = [r for r in records if r["eventName"] not in S3_DATA_EVENTS]
        assert other
        for rec in other:
            assert rec["eventCategory"] == "Management"
            assert rec["managementEvent"] is True
            assert "resources" not in rec

    def test_tls_details_on_api_calls_only(self) -> None:
        records = _records(600)
        api_calls = [r for r in records if r["eventType"] == "AwsApiCall"]
        signins = [r for r in records if r["eventType"] == "AwsConsoleSignIn"]
        assert api_calls and signins
        for rec in api_calls:
            assert rec["tlsDetails"] == {
                "tlsVersion": "TLSv1.3",
                "cipherSuite": "TLS_AES_128_GCM_SHA256",
            }
        for rec in signins:
            assert "tlsDetails" not in rec

    def test_request_id_shape_per_service(self) -> None:
        records = _records(800)
        s3 = [r for r in records if r["eventSource"] == "s3.amazonaws.com"]
        other = [r for r in records if r["eventSource"] != "s3.amazonaws.com"]
        assert s3 and other
        assert {r["eventSource"] for r in other} >= {
            "ec2.amazonaws.com",
            "sts.amazonaws.com",
        }
        for rec in s3:
            assert S3_REQUEST_ID_RE.match(rec["requestID"]), rec["requestID"]
        for rec in other:
            assert UUID4_RE.match(rec["requestID"]), rec["requestID"]

    def test_envelope_mode_wraps_batches_of_ten(self) -> None:
        lines = generate(main, count=100, extra=["--envelope"])
        assert len(lines) == 10
        for line in lines:
            doc = json.loads(line)
            assert set(doc.keys()) == {"Records"}
            assert len(doc["Records"]) == 10
            for rec in doc["Records"]:
                assert rec.keys() >= REQUIRED_KEYS


class TestVpcFlowFormat:
    def test_lines_have_14_typed_fields(self) -> None:
        for line in generate(main, count=400, extra=["--format", "vpcflow"]):
            f = line.split(" ")
            assert len(f) == 14, line
            assert f[0] == "2"
            assert re.fullmatch(r"\d{12}", f[1]), line
            assert ENI_RE.match(f[2]), line
            assert IPV4_RE.match(f[3]) and IPV4_RE.match(f[4]), line
            srcport, dstport = int(f[5]), int(f[6])
            assert 0 <= srcport <= 65535 and 0 <= dstport <= 65535
            assert f[7] in ("1", "6", "17")
            packets, nbytes = int(f[8]), int(f[9])
            assert packets >= 1 and nbytes >= packets
            start, end = int(f[10]), int(f[11])
            assert end >= start
            assert end - start == 60 and start % 60 == 0
            assert f[12] in ("ACCEPT", "REJECT")
            assert f[13] == "OK"

    def test_reject_fraction_realistic(self) -> None:
        lines = generate(main, count=1000, extra=["--format", "vpcflow"])
        rejects = sum(line.split(" ")[12] == "REJECT" for line in lines)
        assert 0.05 < rejects / len(lines) < 0.30


class TestDeterminism:
    def test_same_seed_same_output(self) -> None:
        assert generate(main, count=50) == generate(main, count=50)

    def test_same_seed_same_output_vpcflow(self) -> None:
        extra = ["--format", "vpcflow"]
        assert generate(main, count=50, extra=extra) == generate(main, count=50, extra=extra)

    def test_different_seed_differs(self) -> None:
        assert generate(main, count=50, seed=1) != generate(main, count=50, seed=2)


class TestRealism:
    def test_single_account_everywhere(self) -> None:
        records = _records(300)
        accounts = {r["recipientAccountId"] for r in records}
        accounts |= {r["userIdentity"]["accountId"] for r in records}
        assert len(accounts) == 1
        assert re.fullmatch(r"\d{12}", accounts.pop())

    def test_event_source_variety_and_users_recur(self) -> None:
        records = _records(600)
        sources = {r["eventSource"] for r in records}
        assert {"s3.amazonaws.com", "sts.amazonaws.com", "ec2.amazonaws.com"} <= sources
        users = Counter(
            r["userIdentity"]["userName"] for r in records if r["userIdentity"]["type"] == "IAMUser"
        )
        assert users.most_common(1)[0][1] > 10

    def test_access_denied_rate_low_but_present(self) -> None:
        records = _records(1000)
        denied = [r for r in records if r.get("errorCode") == "AccessDenied"]
        assert 0 < len(denied) / len(records) < 0.08
        for rec in denied:
            assert "is not authorized to perform" in rec["errorMessage"]

    def test_regions_weighted_us_east_1_heavy(self) -> None:
        regions = Counter(r["awsRegion"] for r in _records(800))
        assert regions["us-east-1"] == regions.most_common(1)[0][1]

    def test_enis_recur(self) -> None:
        enis = Counter(
            line.split(" ")[2] for line in generate(main, count=500, extra=["--format", "vpcflow"])
        )
        assert len(enis) <= 12
        assert enis.most_common(1)[0][1] >= 10


class TestScenario:
    @staticmethod
    def _takeover_stats(extra: list[str]) -> tuple[float, float]:
        records = _records(800, backfill="2h", extra=extra)
        failures = sum(
            r["eventName"] == "ConsoleLogin"
            and r["responseElements"].get("ConsoleLogin") == "Failure"
            for r in records
        )
        foreign = sum(r["awsRegion"] == "eu-north-1" for r in records)
        return failures / len(records), foreign / len(records)

    def test_suspicious_login_raises_failures_and_foreign_region(self) -> None:
        base_fail, base_foreign = self._takeover_stats([])
        atk_fail, atk_foreign = self._takeover_stats(["--scenario", "suspicious-login"])
        assert base_fail < 0.01
        assert base_foreign == 0.0
        assert atk_fail > 0.05
        assert atk_foreign > 0.10

    def test_attack_includes_success_assumerole_and_secrets(self) -> None:
        records = _records(800, backfill="2h", extra=["--scenario", "suspicious-login"])
        foreign = [r for r in records if r["sourceIPAddress"] == "185.220.101.34"]
        assert foreign
        victims = {
            r["userIdentity"]["userName"] for r in foreign if r["userIdentity"]["type"] == "IAMUser"
        }
        assert len(victims) == 1  # ONE compromised user
        names = {r["eventName"] for r in foreign}
        assert {"ConsoleLogin", "AssumeRole", "GetSecretValue"} <= names
        assume = next(r for r in foreign if r["eventName"] == "AssumeRole")
        assert assume["requestParameters"]["roleArn"].endswith("role/AdminRole")
        assert any(
            r["eventName"] == "ConsoleLogin" and r["responseElements"]["ConsoleLogin"] == "Success"
            for r in foreign
        )

    def test_vpcflow_scenario_adds_foreign_probes(self) -> None:
        extra = ["--format", "vpcflow"]
        baseline = generate(main, count=800, backfill="2h", extra=extra)
        attack = generate(
            main, count=800, backfill="2h", extra=[*extra, "--scenario", "suspicious-login"]
        )
        assert not any(line.split(" ")[3] == "185.220.101.34" for line in baseline)
        probes = [line for line in attack if line.split(" ")[3] == "185.220.101.34"]
        assert probes
        reject = sum(line.split(" ")[12] == "REJECT" for line in probes)
        assert reject / len(probes) > 0.4
