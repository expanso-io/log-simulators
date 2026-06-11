"""RFC 3164 / RFC 5424 syslog simulator.

Emits the interleaved chatter of a small Linux fleet (edge gateways, app
servers, databases): sshd logins, sudo invocations, cron jobs, systemd unit
churn, kernel events, postfix SMTP traffic, and nginx upstream errors. The
same hosts, users, and IPs recur coherently across lines, and the severity
mix is realistically info-heavy (~70% info, ~13% notice, ~8% warning,
~8% err, <1% crit).

Formats (--rfc):
  5424  RFC 5424 (default): <PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG
  3164  classic BSD syslog: <PRI>Mmm dd hh:mm:ss HOST TAG[pid]: MSG

Scenarios:
  auth-burst  recurring windows that flood ONE target host with sshd
              'Failed password' lines (severity err) from a handful of
              attacker IPs - the brute-force-detection demo
"""

from __future__ import annotations

import argparse
import string
from collections.abc import Callable
from datetime import datetime

from log_simulators.core import (
    BurstSchedule,
    EventFn,
    RunConfig,
    base_parser,
    config_from_args,
    hostnames,
    internal_ips,
    make_faker,
    pick,
    pri,
    public_ips,
    rfc3164_ts,
    rfc5424_ts,
    run,
    usernames,
    zipf_weights,
)

# Syslog severity codes (RFC 5424 numerical values).
CRIT, ERR, WARNING, NOTICE, INFO = 2, 3, 4, 5, 6

# Syslog facility codes.
FAC_KERN = 0  # kernel
FAC_MAIL = 2  # postfix
FAC_DAEMON = 3  # systemd
FAC_AUTH = 4  # sshd
FAC_CRON = 9  # cron
FAC_AUTHPRIV = 10  # sudo
FAC_LOCAL7 = 23  # nginx

UNITS = [
    "nginx.service",
    "postfix.service",
    "cron.service",
    "ssh.service",
    "systemd-tmpfiles-clean.service",
    "logrotate.service",
    "app-worker.service",
    "expanso-edge.service",
    "unattended-upgrades.service",
    "snapd.service",
]
CRON_JOBS = [
    "/usr/local/bin/backup.sh",
    "cd / && run-parts --report /etc/cron.hourly",
    "/usr/bin/certbot renew --quiet",
    "/usr/lib/sysstat/debian-sa1 1 1",
    "/usr/local/bin/rotate-edge-buffers.sh",
    "test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )",
]
SUDO_COMMANDS = [
    "/usr/bin/systemctl restart app-worker",
    "/usr/bin/systemctl reload nginx",
    "/usr/bin/apt-get update",
    "/usr/bin/journalctl -u expanso-edge --since -1h",
    "/bin/cat /var/log/auth.log",
    "/usr/bin/docker ps",
    "/usr/bin/vim /etc/nginx/nginx.conf",
]
BAD_USERS = ["admin", "root", "test", "oracle", "ubuntu", "guest", "pi", "ftpuser"]
KEY_CHARS = string.ascii_letters + string.digits + "+/"

Generator = Callable[[], "tuple[int, str]"]


def build_event_fn(cfg: RunConfig, args: argparse.Namespace) -> EventFn:
    rng = cfg.content_rng()
    fk = make_faker(cfg.seed)

    hosts = hostnames(rng, 4, "edge-gw") + hostnames(rng, 4, "app") + hostnames(rng, 2, "db")
    host_weights = zipf_weights(len(hosts), s=0.6)
    host_ip = dict(zip(hosts, internal_ips(rng, len(hosts), prefix="10.0"), strict=True))
    users = usernames(fk, 18)
    user_weights = zipf_weights(len(users))
    lan_ips = internal_ips(rng, 24, prefix="10.4")
    wan_ips = public_ips(fk, 10)
    attackers = wan_ips[:4]  # reserved for auth-burst; never in normal traffic
    mail_peers = [(fk.domain_name(), ip) for ip in wan_ips[4:]]
    senders = [fk.email() for _ in range(8)]
    stable_pids: dict[tuple[str, str], int] = {}

    burst = BurstSchedule(period=600, length=60) if args.scenario == "auth-burst" else None
    target_host = rng.choice(hosts)

    def src_ip() -> str:
        if rng.random() < 0.85:
            return rng.choice(lan_ips)
        return rng.choice(wan_ips[4:])

    def key_hash() -> str:
        return "".join(rng.choices(KEY_CHARS, k=43))

    def pid_for(host: str, program: str, mode: str) -> int | None:
        if mode == "none":
            return None
        if mode == "one":
            return 1
        if mode == "fresh":
            return rng.randint(1000, 64000)
        key = (host, program)
        if key not in stable_pids:
            stable_pids[key] = rng.randint(300, 4000)
        return stable_pids[key]

    def gen_sshd() -> tuple[int, str]:
        user = pick(rng, users, user_weights)
        ip = src_ip()
        port = rng.randint(1024, 65535)
        roll = rng.random()
        if roll < 0.28:
            return INFO, (
                f"Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:{key_hash()}"
            )
        if roll < 0.48:
            return INFO, f"Accepted password for {user} from {ip} port {port} ssh2"
        if roll < 0.62:
            return INFO, f"pam_unix(sshd:session): session opened for user {user} by (uid=0)"
        if roll < 0.76:
            return INFO, f"pam_unix(sshd:session): session closed for user {user}"
        if roll < 0.84:
            return INFO, f"Connection closed by {ip} port {port} [preauth]"
        if roll < 0.92:
            return WARNING, f"Invalid user {rng.choice(BAD_USERS)} from {ip} port {port}"
        if roll < 0.97:
            return ERR, (
                f"Failed password for invalid user {rng.choice(BAD_USERS)} "
                f"from {ip} port {port} ssh2"
            )
        return ERR, f"Failed password for {user} from {ip} port {port} ssh2"

    def gen_systemd() -> tuple[int, str]:
        unit = rng.choice(UNITS)
        roll = rng.random()
        if roll < 0.38:
            return INFO, f"Started {unit}."
        if roll < 0.52:
            return INFO, f"Starting {unit}..."
        if roll < 0.60:
            return INFO, f"Stopped {unit}."
        if roll < 0.70:
            return INFO, f"{unit}: Deactivated successfully."
        if roll < 0.85:
            return NOTICE, f"Reloading {unit}..."
        if roll < 0.95:
            return NOTICE, f"Reloaded {unit}."
        return ERR, f"Failed to start {unit}."

    def gen_cron() -> tuple[int, str]:
        cron_user = rng.choice(["root", "root", "root", "www-data", "postgres"])
        return INFO, f"({cron_user}) CMD ({rng.choice(CRON_JOBS)})"

    def gen_sudo() -> tuple[int, str]:
        user = pick(rng, users, user_weights)
        roll = rng.random()
        if roll < 0.6:
            return NOTICE, (
                f"{user} : TTY=pts/{rng.randint(0, 4)} ; PWD=/home/{user} ; "
                f"USER=root ; COMMAND={rng.choice(SUDO_COMMANDS)}"
            )
        if roll < 0.8:
            return INFO, (
                f"pam_unix(sudo:session): session opened for user root by "
                f"{user}(uid={rng.randint(1000, 1019)})"
            )
        return INFO, "pam_unix(sudo:session): session closed for user root"

    def gen_postfix() -> tuple[int, str]:
        peer, ip = rng.choice(mail_peers)
        roll = rng.random()
        if roll < 0.42:
            return INFO, f"connect from {peer}[{ip}]"
        if roll < 0.85:
            return INFO, (
                f"disconnect from {peer}[{ip}] ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5"
            )
        if roll < 0.95:
            rcpt = pick(rng, users, user_weights)
            return WARNING, (
                f"NOQUEUE: reject: RCPT from {peer}[{ip}]: 554 5.7.1 Service unavailable; "
                f"client [{ip}] blocked using zen.spamhaus.org; from=<{rng.choice(senders)}> "
                f"to=<{rcpt}@example.com> proto=ESMTP helo=<{peer}>"
            )
        return ERR, f"timeout after DATA from {peer}[{ip}]"

    def gen_kernel() -> tuple[int, str]:
        roll = rng.random()
        if roll < 0.30:
            return INFO, "eth0: Link is Up - 1000Mbps/Full - flow control rx/tx"
        if roll < 0.45:
            return INFO, (
                "EXT4-fs (sda1): mounted filesystem with ordered data mode. Opts: errors=remount-ro"
            )
        if roll < 0.60:
            return WARNING, "eth0: Link is Down"
        if roll < 0.75:
            return WARNING, (
                "TCP: request_sock_TCP: Possible SYN flooding on port 443. Sending cookies."
            )
        if roll < 0.92:
            proc = rng.choice(["app-worker", "nginx", "python3"])
            return ERR, (
                f"{proc}[{rng.randint(1000, 64000)}]: segfault at "
                f"{rng.getrandbits(48):012x} ip 0000{rng.getrandbits(48):012x} "
                f"sp 00007ffd{rng.getrandbits(32):08x} error 4 in libc-2.31.so"
            )
        proc = rng.choice(["app-worker", "java", "python3"])
        return CRIT, (
            f"Out of memory: Killed process {rng.randint(1000, 64000)} ({proc}) "
            f"total-vm:{rng.randint(800_000, 4_000_000)}kB, "
            f"anon-rss:{rng.randint(200_000, 1_500_000)}kB, file-rss:0kB, shmem-rss:0kB"
        )

    def gen_nginx() -> tuple[int, str]:
        upstream = rng.choice(["127.0.0.1:8081", "127.0.0.1:8082", "10.0.0.7:9000"])
        client = src_ip()
        roll = rng.random()
        if roll < 0.45:
            return ERR, (
                f"connect() failed (111: Connection refused) while connecting to upstream, "
                f'client: {client}, server: edge.example.com, request: "GET /api/v1/ingest '
                f'HTTP/1.1", upstream: "http://{upstream}/api/v1/ingest"'
            )
        if roll < 0.60:
            return ERR, (
                f"upstream timed out (110: Connection timed out) while reading response "
                f"header from upstream, client: {client}, server: edge.example.com"
            )
        if roll < 0.85:
            return WARNING, (
                f'limiting requests, excess: {rng.uniform(1, 9):.3f} by zone "perip", '
                f"client: {client}"
            )
        if roll < 0.94:
            return INFO, "signal process started"
        return CRIT, "SSL_do_handshake() failed (SSL: error:0A00006C:SSL routines::bad key share)"

    # (program, facility, pid mode, message generator); weights tuned so the
    # global severity mix lands near 70/13/8/8/<1 info/notice/warning/err/crit.
    programs: list[tuple[str, int, str, Generator]] = [
        ("sshd", FAC_AUTH, "fresh", gen_sshd),
        ("systemd", FAC_DAEMON, "one", gen_systemd),
        ("CRON", FAC_CRON, "fresh", gen_cron),
        ("sudo", FAC_AUTHPRIV, "stable", gen_sudo),
        ("postfix/smtpd", FAC_MAIL, "stable", gen_postfix),
        ("kernel", FAC_KERN, "none", gen_kernel),
        ("nginx", FAC_LOCAL7, "stable", gen_nginx),
    ]
    prog_weights = [30.0, 18.0, 15.0, 12.0, 10.0, 6.0, 5.0]

    def envelope(
        ts: datetime,
        host: str,
        program: str,
        pid: int | None,
        facility: int,
        severity: int,
        msg: str,
    ) -> str:
        prival = pri(facility, severity)
        if args.rfc == "3164":
            tag = program if pid is None else f"{program}[{pid}]"
            return f"<{prival}>{rfc3164_ts(ts)} {host} {tag}: {msg}"
        procid = "-" if pid is None else str(pid)
        return (
            f"<{prival}>1 {rfc5424_ts(ts)} {host} {program} {procid} ID{facility:02d} "
            f'[expanso@32473 ip="{host_ip[host]}"] {msg}'
        )

    def attack_line(ts: datetime) -> str:
        ip = rng.choice(attackers)
        port = rng.randint(1024, 65535)
        victim = rng.choice(BAD_USERS) if rng.random() < 0.7 else "root"
        prefix = "Failed password for invalid user" if victim != "root" else "Failed password for"
        msg = f"{prefix} {victim} from {ip} port {port} ssh2"
        return envelope(
            ts, target_host, "sshd", pid_for(target_host, "sshd", "fresh"), FAC_AUTH, ERR, msg
        )

    def make_event(ts: datetime, seq: int) -> str | None:
        if (
            burst is not None
            and burst.active(ts)
            and rng.random() < 0.6 + 0.35 * burst.intensity(ts)
        ):
            return attack_line(ts)
        host = pick(rng, hosts, host_weights)
        program, facility, pid_mode, gen = pick(rng, programs, prog_weights)
        severity, msg = gen()
        return envelope(
            ts, host, program, pid_for(host, program, pid_mode), facility, severity, msg
        )

    return make_event


def main(argv: list[str] | None = None) -> int:
    parser = base_parser(
        "logsim-syslog",
        "Generate realistic RFC 3164 / RFC 5424 syslog from a small Linux fleet.",
        default_rate=10.0,
    )
    parser.add_argument(
        "--rfc",
        choices=["5424", "3164"],
        default="5424",
        help="syslog wire format: RFC 5424 (default) or classic BSD RFC 3164",
    )
    parser.add_argument(
        "--scenario",
        choices=["none", "auth-burst"],
        default="none",
        help="inject recurring anomaly windows (default: none)",
    )
    args = parser.parse_args(argv)
    cfg = config_from_args(args)
    run(cfg, build_event_fn(cfg, args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
