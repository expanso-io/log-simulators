"""Windows Security Event Log simulator.

Emits Security-channel audit events for a small Active Directory domain
(CORP.EXAMPLE.COM): a domain controller, a SQL server, and a handful of
workstations, with ~20 users whose SIDs stay stable across every event.
Lineage: aronchick/sample-data ``generate.py windows``, rebuilt on the
shared core with realistic per-event-ID payloads.

Event mix (weighted): 4624 successful logon (~55%), 4688 process creation
(~30%), 4672 special privileges (~8%, emitted as the paired follow-up to an
admin 4624 with the same LogonId), 4625 failed logon (~5%), 4720 user
created (~1%), 4740 account lockout (<1%).

Formats:
  xml     one <Event xmlns="...">...</Event> per line, the way the Windows
          Event Log renders a single event (default). --pretty switches to
          indented multi-line XML.
  ndjson  winlogbeat-style flat JSON, one object per line.

Scenarios:
  brute-force  recurring windows where one external IP floods the DC with
               4625 failures (many usernames incl. nonexistent ones,
               LogonType 3, NTLM, Status 0xC000006D / SubStatus 0xC000006A),
               sprinkles 4740 lockouts, and ends each window with a single
               4624 success from the attacker IP - the breach.

Fidelity notes:
  * 4624 and 4688 declare <Version>2</Version> and emit the full version-2
    manifest field set (LogonGuid/ImpersonationLevel/ElevatedToken etc. for
    4624; TargetUser*/MandatoryLabel for 4688).
  * EventRecordID is a per-Computer counter (each machine keeps its own
    event log), seeded with a distinct base and strictly increasing.
  * TimeCreated SystemTime carries 7 fractional digits (100-ns FILETIME
    resolution), like real rendered events.
  * Deliberate deviation: 4672 PrivilegeList joins privileges with ", "
    instead of Windows's newline-per-privilege rendering, preserving the
    one-event-per-line output contract. Intentional, not a fidelity bug.
"""

from __future__ import annotations

import argparse
import json
import string
from datetime import datetime, timezone
from itertools import count
from xml.sax.saxutils import escape

from log_simulators.core import (
    BurstSchedule,
    EventFn,
    RunConfig,
    base_parser,
    config_from_args,
    internal_ips,
    make_faker,
    pick,
    run,
    usernames,
    zipf_weights,
)

XMLNS = "http://schemas.microsoft.com/win/2004/08/events/event"
PROVIDER = "Microsoft-Windows-Security-Auditing"
PROVIDER_GUID = "{54849625-5478-4994-A5BA-3E3B0328C30D}"
DOMAIN = "CORP"
DNS_DOMAIN = "CORP.EXAMPLE.COM"
KEYWORDS_SUCCESS = "0x8020000000000000"
KEYWORDS_FAILURE = "0x8010000000000000"

# event_id -> (Version, Task) as the Security channel reports them.
EVENT_META = {
    4624: (2, 12544),  # An account was successfully logged on
    4625: (0, 12544),  # An account failed to log on
    4672: (0, 12548),  # Special privileges assigned to new logon
    4688: (2, 13312),  # A new process has been created
    4720: (0, 13824),  # A user account was created
    4740: (0, 13824),  # A user account was locked out
}

# Base mix; 4672 rides along as the paired follow-up to admin 4624s (~8% of
# the final stream), so it is absent from the base weights on purpose.
BASE_EVENTS = [4624, 4688, 4625, 4720, 4740]
BASE_WEIGHTS = [55.0, 30.0, 5.0, 1.0, 0.5]

LOGON_TYPES = [3, 2, 10, 5]
LOGON_TYPE_WEIGHTS = [55.0, 20.0, 15.0, 10.0]

_WINLOGON = r"C:\Windows\System32\winlogon.exe"
_SERVICES = r"C:\Windows\System32\services.exe"
_SVCHOST = r"C:\Windows\System32\svchost.exe"

# (image, command line template, parent image)
PROCESS_ZOO: list[tuple[str, str, str]] = [
    (
        r"C:\Windows\System32\svchost.exe",
        r"C:\Windows\System32\svchost.exe -k {svcgroup} -p",
        r"C:\Windows\System32\services.exe",
    ),
    (
        r"C:\Windows\System32\conhost.exe",
        r"\??\C:\Windows\System32\conhost.exe 0xffffffff -ForceV1",
        r"C:\Windows\System32\cmd.exe",
    ),
    (
        r"C:\Windows\System32\cmd.exe",
        r'C:\Windows\System32\cmd.exe /c "{script}"',
        r"C:\Windows\explorer.exe",
    ),
    (
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\{ps1}",
        r"C:\Windows\System32\cmd.exe",
    ),
    (
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer --lang=en-US',
        r"C:\Windows\explorer.exe",
    ),
    (
        r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
        r'"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"',
        r"C:\Windows\explorer.exe",
    ),
    (
        r"C:\Windows\System32\inetsrv\w3wp.exe",
        r'c:\windows\system32\inetsrv\w3wp.exe -ap "DefaultAppPool" -v "v4.0"',
        r"C:\Windows\System32\svchost.exe",
    ),
    (
        r"C:\Windows\System32\taskhostw.exe",
        r"taskhostw.exe {taskarg}",
        r"C:\Windows\System32\svchost.exe",
    ),
    (
        r"C:\Windows\System32\wbem\WmiPrvSE.exe",
        r"C:\Windows\System32\wbem\WmiPrvSE.exe -secured -Embedding",
        r"C:\Windows\System32\svchost.exe",
    ),
    (
        r"C:\Windows\explorer.exe",
        r"C:\Windows\explorer.exe",
        r"C:\Windows\System32\userinit.exe",
    ),
    (
        r"C:\Windows\System32\notepad.exe",
        r'"C:\Windows\System32\notepad.exe" C:\Users\{user}\Documents\{doc}',
        r"C:\Windows\explorer.exe",
    ),
]
ZOO_WEIGHTS = [30.0, 12.0, 10.0, 8.0, 8.0, 6.0, 6.0, 6.0, 5.0, 4.0, 3.0]
SVC_GROUPS = ["netsvcs", "LocalServiceNetworkRestricted", "UnistackSvcGroup", "RPCSS"]
CMD_SCRIPTS = ["whoami /all", "ipconfig /all", "net use", r"dir C:\Temp"]
PS_SCRIPTS = ["backup.ps1", "Get-Inventory.ps1", "sync-ad.ps1", "cleanup.ps1"]
DOCS = ["notes.txt", "todo.txt", "draft.txt"]
TASK_ARGS = [
    "{222A245B-E637-4AE9-A93F-A59CA119A75E}",
    "{0F0B0B86-4D4F-4B4C-8E2E-2BB0C9A4E6D3}",
]
ELEVATION_TYPES = ["%%1938", "%%1936", "%%1937"]
ELEVATION_WEIGHTS = [70.0, 15.0, 15.0]

NULL_GUID = "{00000000-0000-0000-0000-000000000000}"
IMPERSONATION_LEVEL = "%%1833"  # Impersonation
ELEVATED_TOKEN_YES = "%%1842"
ELEVATED_TOKEN_NO = "%%1843"
VIRTUAL_ACCOUNT_NO = "%%1843"
LABEL_MEDIUM = "S-1-16-8192"  # Mandatory Label\Medium Mandatory Level
LABEL_HIGH = "S-1-16-12288"  # Mandatory Label\High Mandatory Level

PRIVILEGES = [
    "SeSecurityPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeDebugPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeLoadDriverPrivilege",
    "SeImpersonatePrivilege",
    "SeDelegateSessionUserImpersonatePrivilege",
    "SeEnableDelegationPrivilege",
    "SeAuditPrivilege",
]

SUBSTATUS = ["0xC000006A", "0xC0000064", "0xC0000072"]  # bad pw / no user / disabled
SUBSTATUS_WEIGHTS = [70.0, 20.0, 10.0]

ATTACK_USERNAMES = [
    "administrator",
    "admin",
    "root",
    "guest",
    "test",
    "sql",
    "backup",
    "oracle",
    "svc_deploy",
    "helpdesk",
]

# XML <Data Name=...> -> flat winlogbeat-ish key. Missing names are dropped.
_NDJSON_KEYS = {
    "SubjectUserSid": "subject_sid",
    "SubjectUserName": "subject_user",
    "SubjectDomainName": "subject_domain",
    "SubjectLogonId": "subject_logon_id",
    "TargetUserSid": "target_sid",
    "TargetSid": "target_sid",
    "TargetUserName": "target_user",
    "TargetDomainName": "target_domain",
    "TargetLogonId": "logon_id",
    "LogonType": "logon_type",
    "LogonProcessName": "logon_process",
    "AuthenticationPackageName": "auth_package",
    "LogonGuid": "logon_guid",
    "ElevatedToken": "elevated_token",
    "MandatoryLabel": "mandatory_label",
    "WorkstationName": "workstation",
    "IpAddress": "source_ip",
    "IpPort": "source_port",
    "ProcessName": "process",
    "NewProcessId": "new_process_id",
    "NewProcessName": "process",
    "TokenElevationType": "token_elevation",
    "ProcessId": "parent_process_id",
    "CommandLine": "command_line",
    "ParentProcessName": "parent_process",
    "PrivilegeList": "privileges",
    "Status": "status",
    "SubStatus": "sub_status",
    "FailureReason": "failure_reason",
    "SamAccountName": "sam_account",
    "UserPrincipalName": "upn",
    "CallerComputerName": "caller_computer",
}
_NDJSON_INTS = {"LogonType", "IpPort"}

# (event_id, keywords, computer FQDN, ordered EventData pairs)
EventParts = tuple[int, str, str, list[tuple[str, str]]]


def _system_time(ts: datetime) -> str:
    """TimeCreated SystemTime: UTC ISO with 7 fractional digits and a Z suffix.

    Real events render FILETIME at 100-ns resolution (7 fractional digits);
    ``datetime`` only carries microseconds, so the 7th digit is synthesized
    deterministically from the microsecond value.
    """
    utc = ts.astimezone(timezone.utc)
    tick = (utc.microsecond // 3) % 10
    return f"{utc.strftime('%Y-%m-%dT%H:%M:%S')}.{utc.microsecond:06d}{tick}Z"


def _render_xml(
    parts: EventParts, systime: str, record_id: int, pid: int, tid: int, pretty: bool
) -> str:
    event_id, keywords, computer, data = parts
    version, task = EVENT_META[event_id]
    system = [
        f'<Provider Name="{PROVIDER}" Guid="{PROVIDER_GUID}"/>',
        f"<EventID>{event_id}</EventID>",
        f"<Version>{version}</Version>",
        "<Level>0</Level>",
        f"<Task>{task}</Task>",
        "<Opcode>0</Opcode>",
        f"<Keywords>{keywords}</Keywords>",
        f'<TimeCreated SystemTime="{systime}"/>',
        f"<EventRecordID>{record_id}</EventRecordID>",
        "<Correlation/>",
        f'<Execution ProcessID="{pid}" ThreadID="{tid}"/>',
        "<Channel>Security</Channel>",
        f"<Computer>{computer}</Computer>",
        "<Security/>",
    ]
    payload = [f'<Data Name="{name}">{escape(value)}</Data>' for name, value in data]
    if not pretty:
        return (
            f'<Event xmlns="{XMLNS}"><System>{"".join(system)}</System>'
            f"<EventData>{''.join(payload)}</EventData></Event>"
        )
    sys_block = "\n    ".join(system)
    data_block = "\n    ".join(payload)
    return (
        f'<Event xmlns="{XMLNS}">\n  <System>\n    {sys_block}\n  </System>\n'
        f"  <EventData>\n    {data_block}\n  </EventData>\n</Event>"
    )


def _render_ndjson(parts: EventParts, ts: datetime, record_id: int) -> str:
    event_id, keywords, computer, data = parts
    utc = ts.astimezone(timezone.utc)
    rec: dict[str, object] = {
        "@timestamp": f"{utc.strftime('%Y-%m-%dT%H:%M:%S')}.{utc.microsecond // 1000:03d}Z",
        "event_id": event_id,
        "record_id": record_id,
        "computer": computer,
        "channel": "Security",
        "provider": PROVIDER,
        "outcome": "failure" if keywords == KEYWORDS_FAILURE else "success",
    }
    for name, value in data:
        key = _NDJSON_KEYS.get(name)
        if event_id == 4624 and name == "ProcessId":
            key = "process_id"  # the logon process, not a creator/parent pid
        if key is None or value == "-":
            continue
        rec[key] = int(value) if name in _NDJSON_INTS and value.isdigit() else value
    return json.dumps(rec, separators=(",", ":"))


def build_event_fn(cfg: RunConfig, args: argparse.Namespace) -> EventFn:
    rng = cfg.content_rng()
    fk = make_faker(cfg.seed)

    # --- entity pools (built once; recur coherently across the stream) ---
    ws: set[str] = set()
    while len(ws) < 4:
        ws.add(f"WS-{rng.randint(100, 999)}")
    workstations = sorted(ws)
    computers = ["WIN-DC01", "WIN-SQL02", *workstations]
    computer_weights = zipf_weights(len(computers))

    users = usernames(fk, 20)
    domain_sid = (
        f"S-1-5-21-{rng.randint(10**8, 10**9 - 1)}"
        f"-{rng.randint(10**8, 10**9 - 1)}-{rng.randint(10**8, 10**9 - 1)}"
    )
    sids = {u: f"{domain_sid}-{1101 + i}" for i, u in enumerate(users)}
    admin_users = sorted(rng.sample(users, 3))
    admin_set = set(admin_users)
    regular_users = [u for u in users if u not in admin_set]
    regular_weights = zipf_weights(len(regular_users))
    user_weights = zipf_weights(len(users))

    ips = internal_ips(rng, 24)
    ip_weights = zipf_weights(len(ips), s=0.8)
    lsass_pid = rng.randint(560, 980)
    rid_counter = count(1200)
    # Each machine keeps its own Security log, so EventRecordID is a
    # per-Computer counter: distinct seeded bases, each strictly increasing.
    record_bases = rng.sample(range(1_000_000, 5_000_000), k=len(computers))
    record_counters = {
        f"{c}.{DNS_DOMAIN}": count(base) for c, base in zip(computers, record_bases, strict=True)
    }

    # --- brute-force scenario state ---
    storm = BurstSchedule(period=600, length=60) if args.scenario == "brute-force" else None
    fake_users = [fk.user_name() for _ in range(6)]
    attack_users = ATTACK_USERNAMES + fake_users
    attacker_ip = fk.ipv4_public()
    alphabet = string.ascii_uppercase + string.digits
    attacker_host = "DESKTOP-" + "".join(rng.choice(alphabet) for _ in range(7))
    compromised = rng.choice(admin_users)
    breached: set[int] = set()

    # 4672 events queued to follow the admin 4624 that earned them.
    pending: list[tuple[str, str, str, str]] = []

    def fqdn(computer: str) -> str:
        return f"{computer}.{DNS_DOMAIN}"

    def new_logon_id() -> str:
        return f"0x{rng.randrange(0x10000, 0xFFFFFFF):X}"

    def new_logon_guid() -> str:
        raw = f"{rng.getrandbits(128):032X}"
        return f"{{{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:]}}}"

    def pick_target_user() -> str:
        if rng.random() < 0.15:
            return rng.choice(admin_users)
        return pick(rng, regular_users, regular_weights)

    def logon_context(ltype: int, computer: str) -> tuple[str, str, str, str, str, str]:
        """(logon_process, auth_package, workstation, ip, port, process_name)."""
        if ltype == 2:
            return ("User32", "Negotiate", computer, "127.0.0.1", "0", _WINLOGON)
        if ltype == 5:
            return ("Advapi", "Negotiate", computer, "-", "-", _SERVICES)
        wkst = rng.choice(workstations)
        ip = pick(rng, ips, ip_weights)
        port = str(rng.randint(49152, 65535))
        if ltype == 10:
            return ("User32", "Negotiate", wkst, ip, port, _SVCHOST)
        if rng.random() < 0.8:
            return ("Kerberos", "Kerberos", wkst, ip, port, "-")
        return ("NtLmSsp", "NTLM", wkst, ip, port, "-")

    def make_4624(breach: bool = False) -> EventParts:
        if breach:
            computer = "WIN-DC01"
            user = compromised
            ltype = 3
            ctx = ("NtLmSsp", "NTLM", attacker_host, attacker_ip, str(rng.randint(49152, 65535)))
            lproc, auth, wkst, ip, port = ctx
            proc = "-"
        else:
            computer = pick(rng, computers, computer_weights)
            user = pick_target_user()
            ltype = pick(rng, LOGON_TYPES, LOGON_TYPE_WEIGHTS)
            lproc, auth, wkst, ip, port, proc = logon_context(ltype, computer)
        logon_id = new_logon_id()
        if user in admin_set:
            pending.append((user, sids[user], logon_id, fqdn(computer)))
        # Version-2 manifest correlations: Kerberos logons carry a real
        # LogonGuid (NTLM/Negotiate render the null GUID), NTLM reports its
        # LM package and 128-bit session key, and admins get an elevated
        # token. ProcessId/ProcessName are 0x0/- for network logons.
        guid = new_logon_guid() if auth == "Kerberos" else NULL_GUID
        lm_package, key_length = ("NTLM V2", "128") if auth == "NTLM" else ("-", "0")
        proc_id = "0x0" if proc == "-" else f"0x{rng.randint(0x200, 0x9FFF):x}"
        elevated = ELEVATED_TOKEN_YES if user in admin_set else ELEVATED_TOKEN_NO
        data = [
            ("SubjectUserSid", "S-1-5-18"),
            ("SubjectUserName", f"{computer}$"),
            ("SubjectDomainName", DOMAIN),
            ("SubjectLogonId", "0x3E7"),
            ("TargetUserSid", sids[user]),
            ("TargetUserName", user),
            ("TargetDomainName", DOMAIN),
            ("TargetLogonId", logon_id),
            ("LogonType", str(ltype)),
            ("LogonProcessName", lproc),
            ("AuthenticationPackageName", auth),
            ("WorkstationName", wkst),
            ("LogonGuid", guid),
            ("TransmittedServices", "-"),
            ("LmPackageName", lm_package),
            ("KeyLength", key_length),
            ("ProcessId", proc_id),
            ("ProcessName", proc),
            ("IpAddress", ip),
            ("IpPort", port),
            ("ImpersonationLevel", IMPERSONATION_LEVEL),
            ("RestrictedAdminMode", "-"),
            ("TargetOutboundUserName", "-"),
            ("TargetOutboundDomainName", "-"),
            ("VirtualAccount", VIRTUAL_ACCOUNT_NO),
            ("TargetLinkedLogonId", "0x0"),
            ("ElevatedToken", elevated),
        ]
        return 4624, KEYWORDS_SUCCESS, fqdn(computer), data

    def make_4625(flood: bool = False) -> EventParts:
        if flood:
            computer = "WIN-DC01"
            user = (
                pick(rng, users, user_weights) if rng.random() < 0.3 else rng.choice(attack_users)
            )
            ltype, lproc, auth = 3, "NtLmSsp", "NTLM"
            wkst, ip = attacker_host, attacker_ip
            port = str(rng.randint(1024, 65535))
            sub_status = "0xC000006A"
        else:
            computer = pick(rng, computers, computer_weights)
            user = pick(rng, users, user_weights)
            ltype = pick(rng, LOGON_TYPES, LOGON_TYPE_WEIGHTS)
            lproc, auth, wkst, ip, port, _ = logon_context(ltype, computer)
            sub_status = pick(rng, SUBSTATUS, SUBSTATUS_WEIGHTS)
        data = [
            ("SubjectUserSid", "S-1-5-18"),
            ("SubjectUserName", f"{computer}$"),
            ("SubjectDomainName", DOMAIN),
            ("SubjectLogonId", "0x3E7"),
            ("TargetUserSid", "S-1-0-0"),
            ("TargetUserName", user),
            ("TargetDomainName", DOMAIN),
            ("Status", "0xC000006D"),
            ("FailureReason", "%%2313"),
            ("SubStatus", sub_status),
            ("LogonType", str(ltype)),
            ("LogonProcessName", lproc),
            ("AuthenticationPackageName", auth),
            ("WorkstationName", wkst),
            ("IpAddress", ip),
            ("IpPort", port),
            ("ProcessName", "-"),
        ]
        return 4625, KEYWORDS_FAILURE, fqdn(computer), data

    def make_4672(user: str, sid: str, logon_id: str, computer: str) -> EventParts:
        """Special privileges assigned to new logon.

        PrivilegeList is deliberately ", "-joined rather than Windows's
        newline-per-privilege rendering: the simulator's output contract is
        one event per line, so the single-line form wins. Not a fidelity bug.
        """
        idx = sorted(rng.sample(range(len(PRIVILEGES)), k=rng.randint(4, 8)))
        privs = ", ".join(PRIVILEGES[i] for i in idx)
        data = [
            ("SubjectUserSid", sid),
            ("SubjectUserName", user),
            ("SubjectDomainName", DOMAIN),
            ("SubjectLogonId", logon_id),
            ("PrivilegeList", privs),
        ]
        return 4672, KEYWORDS_SUCCESS, computer, data

    def make_4688() -> EventParts:
        computer = pick(rng, computers, computer_weights)
        user = pick_target_user()
        image, template, parent = pick(rng, PROCESS_ZOO, ZOO_WEIGHTS)
        cmdline = template.format(
            svcgroup=rng.choice(SVC_GROUPS),
            script=rng.choice(CMD_SCRIPTS),
            ps1=rng.choice(PS_SCRIPTS),
            taskarg=rng.choice(TASK_ARGS),
            user=user,
            doc=rng.choice(DOCS),
        )
        # Version-2 manifest fields: TargetUser* stay at their no-cross-user
        # defaults, and the integrity label correlates with the subject -
        # admins run High (S-1-16-12288), everyone else Medium (S-1-16-8192).
        label = LABEL_HIGH if user in admin_set else LABEL_MEDIUM
        data = [
            ("SubjectUserSid", sids[user]),
            ("SubjectUserName", user),
            ("SubjectDomainName", DOMAIN),
            ("SubjectLogonId", new_logon_id()),
            ("NewProcessId", f"0x{rng.randint(0x400, 0x9FFF):x}"),
            ("NewProcessName", image),
            ("TokenElevationType", pick(rng, ELEVATION_TYPES, ELEVATION_WEIGHTS)),
            ("ProcessId", f"0x{rng.randint(0x400, 0x9FFF):x}"),
            ("CommandLine", cmdline),
            ("TargetUserSid", "S-1-0-0"),
            ("TargetUserName", "-"),
            ("TargetDomainName", "-"),
            ("TargetLogonId", "0x0"),
            ("ParentProcessName", parent),
            ("MandatoryLabel", label),
        ]
        return 4688, KEYWORDS_SUCCESS, fqdn(computer), data

    def make_4720() -> EventParts:
        new_user = fk.user_name()
        new_sid = f"{domain_sid}-{next(rid_counter)}"
        admin = rng.choice(admin_users)
        data = [
            ("TargetUserName", new_user),
            ("TargetDomainName", DOMAIN),
            ("TargetSid", new_sid),
            ("SubjectUserSid", sids[admin]),
            ("SubjectUserName", admin),
            ("SubjectDomainName", DOMAIN),
            ("SubjectLogonId", new_logon_id()),
            ("SamAccountName", new_user),
            ("UserPrincipalName", f"{new_user}@{DNS_DOMAIN.lower()}"),
        ]
        return 4720, KEYWORDS_SUCCESS, fqdn("WIN-DC01"), data

    def make_4740(user: str, attacker: bool = False) -> EventParts:
        caller = attacker_host if attacker else rng.choice(workstations)
        data = [
            ("TargetUserName", user),
            ("TargetDomainName", DOMAIN),
            ("TargetSid", sids.get(user, "S-1-0-0")),
            ("CallerComputerName", caller),
            ("SubjectUserSid", "S-1-5-18"),
            ("SubjectUserName", "WIN-DC01$"),
            ("SubjectDomainName", DOMAIN),
            ("SubjectLogonId", "0x3E7"),
        ]
        return 4740, KEYWORDS_SUCCESS, fqdn("WIN-DC01"), data

    def make_base() -> EventParts:
        event_id = pick(rng, BASE_EVENTS, BASE_WEIGHTS)
        if event_id == 4624:
            return make_4624()
        if event_id == 4625:
            return make_4625()
        if event_id == 4688:
            return make_4688()
        if event_id == 4720:
            return make_4720()
        return make_4740(pick(rng, users, user_weights))

    def make_event(ts: datetime, _seq: int) -> str:
        if pending:
            parts = make_4672(*pending.pop(0))
        elif storm is not None and storm.active(ts):
            window = int(ts.timestamp() // storm.period)
            offset = ts.timestamp() % storm.period
            if window not in breached and offset > storm.length - 6.0:
                breached.add(window)
                parts = make_4624(breach=True)
            else:
                roll = rng.random()
                if roll < 0.04:
                    parts = make_4740(pick(rng, users, user_weights), attacker=True)
                elif roll < 0.70 + 0.25 * storm.intensity(ts):
                    parts = make_4625(flood=True)
                else:
                    parts = make_base()
        else:
            parts = make_base()
        record_id = next(record_counters[parts[2]])
        if args.format == "ndjson":
            return _render_ndjson(parts, ts, record_id)
        tid = rng.randint(1000, 9900)
        return _render_xml(parts, _system_time(ts), record_id, lsass_pid, tid, args.pretty)

    return make_event


def main(argv: list[str] | None = None) -> int:
    parser = base_parser(
        "logsim-windows",
        "Generate realistic Windows Security Event Log events "
        "(4624/4625/4672/4688/4720/4740) for a small AD domain.",
        default_rate=10.0,
    )
    parser.add_argument(
        "--format",
        choices=["xml", "ndjson"],
        default="xml",
        help="output format: single-line Event XML or winlogbeat-style JSON (default: xml)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="indent XML events across multiple lines (xml format only)",
    )
    parser.add_argument(
        "--scenario",
        choices=["none", "brute-force"],
        default="none",
        help="inject recurring anomaly windows (default: none)",
    )
    args = parser.parse_args(argv)
    cfg = config_from_args(args)
    run(cfg, build_event_fn(cfg, args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
