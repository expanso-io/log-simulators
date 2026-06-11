"""AWS CloudTrail + VPC Flow Log simulator.

Models one AWS account with a stable cast: ~15 IAM users and 5 roles with
fixed principalIds/ARNs, a weighted region footprint (us-east-1 heavy), an
ENI fleet with stable private IPs, and realistic bucket/secret/instance
pools - so the same identities recur coherently across records.

Formats:
  cloudtrail  one CloudTrail Record JSON object per line (default; NDJSON).
              Every record carries eventCategory + managementEvent;
              S3 GetObject/PutObject are data-plane (eventCategory "Data",
              resources[] for the object + bucket, 16-char uppercase-hex
              S3 request IDs) while everything else is "Management" with
              UUID request IDs. API-call records include tlsDetails.
              With --envelope, batches of 10 records are wrapped in the
              {"Records": [...]} envelope (one envelope per line) for
              S3-delivered-file realism; a trailing partial batch (< 10
              records at end of run) is dropped.
  vpcflow     VPC Flow Logs v2, space-delimited, 14 fields:
              version account-id interface-id srcaddr dstaddr srcport
              dstport protocol packets bytes start end action log-status.
              start/end are UNIX epoch ints on 60-second windows derived
              from the event timestamp; ~15% REJECT; protocols 6/17/1.

Scenarios:
  suspicious-login  recurring account-takeover windows: ConsoleLogin
                    failures then a success for ONE real user from
                    eu-north-1 + a foreign IP, followed by AssumeRole into
                    the admin role and a GetSecretValue burst. In vpcflow
                    format the same windows show REJECT-heavy probes from
                    the foreign IP.
"""

from __future__ import annotations

import argparse
import json
import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from log_simulators.core import (
    USER_AGENTS,
    BurstSchedule,
    EventFn,
    RunConfig,
    base_parser,
    config_from_args,
    lognormal_int,
    make_faker,
    pick,
    run,
    usernames,
    zipf_weights,
)

REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-2"]
REGION_WEIGHTS = [60.0, 20.0, 12.0, 8.0]
ATTACK_REGION = "eu-north-1"
FOREIGN_IP = "185.220.101.34"  # known Tor exit range

ROLE_NAMES = ["AdminRole", "DeployRole", "ReadOnlyAuditor", "DataPipelineRole", "LambdaExecRole"]
ADMIN_ROLE = "AdminRole"

BUCKETS = [
    "acme-prod-data-lake",
    "acme-app-logs",
    "acme-ml-artifacts",
    "acme-customer-exports",
    "acme-terraform-state",
]
SECRETS = [
    "prod/db/postgres-master",
    "prod/api/stripe-key",
    "prod/oauth/google-client",
    "staging/db/postgres",
    "prod/ssh/deploy-key",
]
POLICY_ARNS = [
    "arn:aws:iam::aws:policy/ReadOnlyAccess",
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/AdministratorAccess",
]
API_AGENTS = [
    "aws-cli/2.15.30 Python/3.11.6 Linux/5.15.0-101-generic exe/x86_64.ubuntu.22",
    "Boto3/1.34.51 md/Botocore#1.34.51 ua/2.0 os/linux#5.15 lang/python#3.11.6",
    "aws-sdk-go/1.50.25 (go1.21.5; linux; amd64)",
    "aws-sdk-java/2.25.11 Linux/5.10 OpenJDK_64-Bit_Server_VM/17.0.9",
    "console.amazonaws.com",
    "APN/1.0 HashiCorp/1.0 Terraform/1.7.4",
]

# (eventName, weight) for the normal CloudTrail traffic mix.
EVENT_MIX = [
    ("ConsoleLogin", 8.0),
    ("AssumeRole", 20.0),
    ("GetObject", 60.0),
    ("PutObject", 24.0),
    ("DescribeInstances", 28.0),
    ("RunInstances", 4.0),
    ("GetSecretValue", 12.0),
    ("CreateUser", 1.0),
    ("AttachUserPolicy", 1.0),
]
IAM_ACTION = {
    "GetObject": "s3:GetObject",
    "PutObject": "s3:PutObject",
    "DescribeInstances": "ec2:DescribeInstances",
    "RunInstances": "ec2:RunInstances",
    "GetSecretValue": "secretsmanager:GetSecretValue",
    "CreateUser": "iam:CreateUser",
    "AttachUserPolicy": "iam:AttachUserPolicy",
    "AssumeRole": "sts:AssumeRole",
}
ACCESS_DENIED_RATE = 0.03
LOGIN_FAILURE_RATE = 0.02

PROTOCOLS = [6, 17, 1]
PROTOCOL_WEIGHTS = [75.0, 20.0, 5.0]
TCP_PORTS = [443, 80, 22, 3306, 5432, 8080]
TCP_PORT_WEIGHTS = [50.0, 18.0, 8.0, 5.0, 4.0, 5.0]
UDP_PORTS = [53, 123, 443]
ATTACK_PORTS = [22, 443, 3389]
REJECT_RATE = 0.15

_ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
ENVELOPE_BATCH = 10


@dataclass(frozen=True)
class IamUser:
    name: str
    principal_id: str
    arn: str
    home_region: str
    ip: str
    browser_agent: str
    api_agent: str


@dataclass(frozen=True)
class IamRole:
    name: str
    role_id: str
    arn: str


def _aws_id(rng: random.Random, prefix: str) -> str:
    return prefix + "".join(rng.choice(_ID_ALPHABET) for _ in range(17))


def _hex_id(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _event_time(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_event_fn(cfg: RunConfig, args: argparse.Namespace) -> EventFn:
    rng = cfg.content_rng()
    fk = make_faker(cfg.seed)

    account = f"{rng.randrange(100_000_000_000, 1_000_000_000_000)}"
    user_names = usernames(fk, 15)
    users = [
        IamUser(
            name=name,
            principal_id=_aws_id(rng, "AIDA"),
            arn=f"arn:aws:iam::{account}:user/{name}",
            home_region=pick(rng, REGIONS, REGION_WEIGHTS),
            ip=fk.ipv4_public(),
            browser_agent=rng.choice(USER_AGENTS[:9]),
            api_agent=rng.choice(API_AGENTS),
        )
        for name in user_names
    ]
    user_weights = zipf_weights(len(users))
    roles = [
        IamRole(
            name=name,
            role_id=_aws_id(rng, "AROA"),
            arn=f"arn:aws:iam::{account}:role/{name}",
        )
        for name in ROLE_NAMES
    ]
    admin_role = next(r for r in roles if r.name == ADMIN_ROLE)
    instance_ids = [f"i-0{_hex_id(rng, 16)}" for _ in range(8)]
    s3_keys = [
        f"{rng.choice(['data/2026/01', 'logs/app', 'exports', 'ml/models', 'backups'])}/"
        f"{fk.word()}-{rng.randint(1, 9999):04d}."
        f"{rng.choice(['parquet', 'csv', 'json.gz', 'log.gz', 'bin'])}"
        for _ in range(25)
    ]
    bucket_weights = zipf_weights(len(BUCKETS))

    enis = [f"eni-0{_hex_id(rng, 16)}" for _ in range(12)]
    eni_weights = zipf_weights(len(enis), s=0.9)
    eni_ip = {eni: f"172.31.{rng.randint(16, 31)}.{rng.randint(1, 254)}" for eni in enis}
    remote_ips = [fk.ipv4_public() for _ in range(40)]
    remote_weights = zipf_weights(len(remote_ips), s=0.8)

    storm = BurstSchedule(period=600, length=60) if args.scenario == "suspicious-login" else None
    victim = pick(rng, users, user_weights)
    attack_step = 0
    envelope_buf: list[dict[str, Any]] = []

    def iam_identity(user: IamUser) -> dict[str, Any]:
        return {
            "type": "IAMUser",
            "principalId": user.principal_id,
            "arn": user.arn,
            "accountId": account,
            "userName": user.name,
        }

    def role_identity(role: IamRole, session: str, ts: datetime) -> dict[str, Any]:
        return {
            "type": "AssumedRole",
            "principalId": f"{role.role_id}:{session}",
            "arn": f"arn:aws:sts::{account}:assumed-role/{role.name}/{session}",
            "accountId": account,
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": role.role_id,
                    "arn": role.arn,
                    "accountId": account,
                    "userName": role.name,
                },
                "attributes": {
                    "creationDate": _event_time(ts),
                    "mfaAuthenticated": "false",
                },
            },
        }

    def base_record(
        ts: datetime,
        identity: dict[str, Any],
        source: str,
        name: str,
        region: str,
        ip: str,
        agent: str,
        event_type: str = "AwsApiCall",
    ) -> dict[str, Any]:
        rec: dict[str, Any] = {
            "eventVersion": "1.08",
            "userIdentity": identity,
            "eventTime": _event_time(ts),
            "eventSource": source,
            "eventName": name,
            "awsRegion": region,
            "sourceIPAddress": ip,
            "userAgent": agent,
            "requestParameters": None,
            "responseElements": None,
            "requestID": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
            "eventID": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
            "eventType": event_type,
            "recipientAccountId": account,
            "eventCategory": "Management",
            "managementEvent": True,
        }
        if event_type == "AwsApiCall":
            rec["tlsDetails"] = {
                "tlsVersion": "TLSv1.3",
                "cipherSuite": "TLS_AES_128_GCM_SHA256",
            }
        return rec

    def deny(rec: dict[str, Any], identity_arn: str, name: str, resource: str) -> None:
        rec["errorCode"] = "AccessDenied"
        rec["errorMessage"] = (
            f"User: {identity_arn} is not authorized to perform: "
            f"{IAM_ACTION[name]} on resource: {resource}"
        )
        rec["responseElements"] = None

    def console_login(
        ts: datetime, user: IamUser, region: str, ip: str, success: bool
    ) -> dict[str, Any]:
        rec = base_record(
            ts,
            iam_identity(user),
            "signin.amazonaws.com",
            "ConsoleLogin",
            region,
            ip,
            user.browser_agent,
            event_type="AwsConsoleSignIn",
        )
        rec["responseElements"] = {"ConsoleLogin": "Success" if success else "Failure"}
        rec["additionalEventData"] = {
            "MFAUsed": "Yes" if success and rng.random() < 0.7 else "No",
            "MobileVersion": "No",
            "LoginTo": "https://console.aws.amazon.com/console/home",
        }
        if not success:
            rec["errorMessage"] = "Failed authentication"
        return rec

    def assume_role(
        ts: datetime, user: IamUser, role: IamRole, region: str, ip: str
    ) -> dict[str, Any]:
        session = f"{user.name}-session"
        rec = base_record(
            ts, iam_identity(user), "sts.amazonaws.com", "AssumeRole", region, ip, user.api_agent
        )
        rec["requestParameters"] = {"roleArn": role.arn, "roleSessionName": session}
        rec["responseElements"] = {
            "assumedRoleUser": {
                "assumedRoleId": f"{role.role_id}:{session}",
                "arn": f"arn:aws:sts::{account}:assumed-role/{role.name}/{session}",
            }
        }
        rec["readOnly"] = False
        return rec

    def api_actor(ts: datetime, user: IamUser) -> tuple[dict[str, Any], str]:
        """Return (identity, arn): the user directly, or one of their role sessions."""
        if rng.random() < 0.25:
            role = rng.choice(roles)
            ident = role_identity(role, f"{user.name}-session", ts)
            return ident, str(ident["arn"])
        return iam_identity(user), user.arn

    def normal_record(ts: datetime) -> dict[str, Any]:
        name = pick(rng, [n for n, _ in EVENT_MIX], [w for _, w in EVENT_MIX])
        user = pick(rng, users, user_weights)
        region = user.home_region if rng.random() < 0.9 else pick(rng, REGIONS, REGION_WEIGHTS)
        ip = user.ip

        if name == "ConsoleLogin":
            return console_login(ts, user, region, ip, rng.random() >= LOGIN_FAILURE_RATE)
        if name == "AssumeRole":
            return assume_role(ts, user, rng.choice(roles), region, ip)

        identity, arn = api_actor(ts, user)
        if name in ("CreateUser", "AttachUserPolicy"):
            region, identity, arn = "us-east-1", iam_identity(user), user.arn
        source = {
            "GetObject": "s3.amazonaws.com",
            "PutObject": "s3.amazonaws.com",
            "DescribeInstances": "ec2.amazonaws.com",
            "RunInstances": "ec2.amazonaws.com",
            "GetSecretValue": "secretsmanager.amazonaws.com",
            "CreateUser": "iam.amazonaws.com",
            "AttachUserPolicy": "iam.amazonaws.com",
        }[name]
        rec = base_record(ts, identity, source, name, region, ip, user.api_agent)
        rec["readOnly"] = name in ("GetObject", "DescribeInstances", "GetSecretValue")
        resource = "*"
        if name in ("GetObject", "PutObject"):
            bucket = pick(rng, BUCKETS, bucket_weights)
            key = rng.choice(s3_keys)
            rec["requestParameters"] = {
                "bucketName": bucket,
                "Host": f"{bucket}.s3.amazonaws.com",
                "key": key,
            }
            # S3 object ops are data-plane events with their own request-ID format.
            rec["requestID"] = _hex_id(rng, 16).upper()
            rec["eventCategory"] = "Data"
            rec["managementEvent"] = False
            rec["resources"] = [
                {"type": "AWS::S3::Object", "ARN": f"arn:aws:s3:::{bucket}/{key}"},
                {
                    "accountId": account,
                    "type": "AWS::S3::Bucket",
                    "ARN": f"arn:aws:s3:::{bucket}",
                },
            ]
            resource = f"arn:aws:s3:::{bucket}"
        elif name == "DescribeInstances":
            rec["requestParameters"] = {"instancesSet": {}, "filterSet": {}}
        elif name == "RunInstances":
            instance = rng.choice(instance_ids)
            itype = rng.choice(["t3.micro", "t3.medium", "m6i.large", "c6i.xlarge"])
            rec["requestParameters"] = {
                "instanceType": itype,
                "minCount": 1,
                "maxCount": 1,
                "imageId": f"ami-0{_hex_id(rng, 16)}",
            }
            rec["responseElements"] = {
                "instancesSet": {"items": [{"instanceId": instance, "instanceType": itype}]}
            }
        elif name == "GetSecretValue":
            secret = rng.choice(SECRETS)
            rec["requestParameters"] = {"secretId": secret}
            resource = f"arn:aws:secretsmanager:{region}:{account}:secret:{secret}"
        elif name == "CreateUser":
            new_user = f"{fk.user_name()}{rng.randint(10, 99)}"
            rec["requestParameters"] = {"userName": new_user}
            rec["responseElements"] = {
                "user": {
                    "userName": new_user,
                    "arn": f"arn:aws:iam::{account}:user/{new_user}",
                }
            }
        elif name == "AttachUserPolicy":
            rec["requestParameters"] = {
                "userName": rng.choice(user_names),
                "policyArn": rng.choice(POLICY_ARNS),
            }
        if rng.random() < ACCESS_DENIED_RATE:
            deny(rec, arn, name, resource)
        return rec

    def attack_record(ts: datetime) -> dict[str, Any]:
        """Account-takeover sequence: failed logins -> success -> AssumeRole -> secrets."""
        nonlocal attack_step
        step = attack_step % 10
        attack_step += 1
        if step < 4:
            return console_login(ts, victim, ATTACK_REGION, FOREIGN_IP, success=False)
        if step == 4:
            return console_login(ts, victim, ATTACK_REGION, FOREIGN_IP, success=True)
        if step == 5:
            return assume_role(ts, victim, admin_role, ATTACK_REGION, FOREIGN_IP)
        session = f"{victim.name}-session"
        rec = base_record(
            ts,
            role_identity(admin_role, session, ts),
            "secretsmanager.amazonaws.com",
            "GetSecretValue",
            ATTACK_REGION,
            FOREIGN_IP,
            "aws-cli/2.15.30 Python/3.11.6 Linux/5.15.0-101-generic exe/x86_64.ubuntu.22",
        )
        rec["readOnly"] = True
        rec["requestParameters"] = {"secretId": rng.choice(SECRETS)}
        return rec

    def cloudtrail_record(ts: datetime) -> dict[str, Any]:
        if (
            storm is not None
            and storm.active(ts)
            and rng.random() < 0.4 + 0.5 * storm.intensity(ts)
        ):
            return attack_record(ts)
        return normal_record(ts)

    def vpcflow_line(ts: datetime) -> str:
        start = int(ts.timestamp()) // 60 * 60
        end = start + 60
        eni = pick(rng, enis, eni_weights)
        local = eni_ip[eni]

        if storm is not None and storm.active(ts) and rng.random() < 0.6:
            src, dst = FOREIGN_IP, local
            srcport = rng.randint(1024, 65535)
            dstport = rng.choice(ATTACK_PORTS)
            protocol = 6
            action = "REJECT" if rng.random() < 0.7 else "ACCEPT"
        else:
            protocol = pick(rng, PROTOCOLS, PROTOCOL_WEIGHTS)
            remote = pick(rng, remote_ips, remote_weights)
            outbound = rng.random() < 0.5
            src, dst = (local, remote) if outbound else (remote, local)
            if protocol == 1:
                srcport = dstport = 0
            else:
                service = (
                    pick(rng, TCP_PORTS, TCP_PORT_WEIGHTS)
                    if protocol == 6
                    else rng.choice(UDP_PORTS)
                )
                ephemeral = rng.randint(1024, 65535)
                srcport, dstport = (ephemeral, service) if outbound else (service, ephemeral)
            action = "REJECT" if rng.random() < REJECT_RATE else "ACCEPT"

        if action == "REJECT":
            packets = rng.randint(1, 4)
            nbytes = packets * rng.randint(40, 120)
        else:
            packets = lognormal_int(rng, 12, 1.0, lo=1, hi=50_000)
            nbytes = packets * rng.randint(60, 1400)
        return (
            f"2 {account} {eni} {src} {dst} {srcport} {dstport} "
            f"{protocol} {packets} {nbytes} {start} {end} {action} OK"
        )

    def make_event(ts: datetime, seq: int) -> str | None:
        if args.format == "vpcflow":
            return vpcflow_line(ts)
        rec = cloudtrail_record(ts)
        if not args.envelope:
            return json.dumps(rec, separators=(",", ":"))
        envelope_buf.append(rec)
        if len(envelope_buf) < ENVELOPE_BATCH:
            return None
        out = json.dumps({"Records": envelope_buf}, separators=(",", ":"))
        envelope_buf.clear()
        return out

    return make_event


def main(argv: list[str] | None = None) -> int:
    parser = base_parser(
        "logsim-cloud",
        "Generate realistic AWS CloudTrail audit records and VPC Flow Logs.",
        default_rate=10.0,
    )
    parser.add_argument(
        "--format",
        choices=["cloudtrail", "vpcflow"],
        default="cloudtrail",
        help="output format (default: cloudtrail)",
    )
    parser.add_argument(
        "--envelope",
        action="store_true",
        help='cloudtrail only: wrap batches of 10 records in the {"Records":[...]} envelope',
    )
    parser.add_argument(
        "--scenario",
        choices=["none", "suspicious-login"],
        default="none",
        help="inject recurring anomaly windows (default: none)",
    )
    args = parser.parse_args(argv)
    cfg = config_from_args(args)
    run(cfg, build_event_fn(cfg, args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
