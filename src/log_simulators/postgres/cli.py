"""PostgreSQL server log simulator (stderr, csvlog, jsonlog).

Models a small OLTP postgres server (shopdb + analytics) with a pool of
backend sessions. Connections open and close (with session durations),
slow queries log ``duration: ... ms  statement: ...`` lines, the
checkpointer emits starting/complete pairs, autovacuum workers report on
the app tables, and a realistic ERROR family (duplicate key, deadlock,
statement timeout, missing relation, syntax error) carries
DETAIL/HINT/STATEMENT continuation lines.

Formats:
  stderr   postmaster stderr with log_line_prefix '%m [%p] %q%u@%d '
           (default). ERROR events include their DETAIL/HINT/STATEMENT
           continuation lines (same timestamp + pid) in ONE event string,
           making this the multiline-reassembly demo fixture.
  csvlog   postgres csvlog: one CSV record per event with the full
           fixed-width PG14+ 26-column schema (log_time .. query_id);
           absent values are empty fields.
  jsonlog  PG15+ structured logging, one JSON object per line with
           separate remote_host / remote_port fields.

Scenarios:
  deadlock  recurring burst windows of deadlock storms: 'deadlock detected'
            ERROR events with matching reciprocal events from the blocking
            pid, plus lock-wait LOG lines.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from log_simulators.core import (
    BurstSchedule,
    EventFn,
    RunConfig,
    base_parser,
    config_from_args,
    internal_ips,
    lognormal_int,
    pick,
    run,
)

DB_USERS = ["app_user", "analytics_ro", "admin"]
USER_WEIGHTS = [0.65, 0.22, 0.13]
USER_DB = {"app_user": "shopdb", "analytics_ro": "analytics", "admin": "shopdb"}
USER_APPS = {
    "app_user": ["shop-api", "shop-worker"],
    "analytics_ro": ["dbt", "metabase"],
    "admin": ["psql", "pgAdmin 4 - CONN:1"],
}
TABLES = ["users", "orders", "products", "inventory", "sessions"]

QUERIES: list[tuple[str, str]] = [
    ("SELECT", "SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20"),
    (
        "SELECT",
        "SELECT o.id, o.total, u.email FROM orders o JOIN users u ON u.id = o.user_id "
        "WHERE o.status = $1",
    ),
    ("SELECT", "SELECT count(*) FROM sessions WHERE last_seen_at > now() - interval '15 minutes'"),
    ("SELECT", "SELECT id, name, price FROM products WHERE category = $1 AND price < $2 LIMIT 50"),
    (
        "SELECT",
        "SELECT p.id, p.name, i.quantity FROM products p JOIN inventory i "
        "ON i.product_id = p.id WHERE i.quantity < $1",
    ),
    ("INSERT", "INSERT INTO orders (user_id, total, status) VALUES ($1, $2, $3) RETURNING id"),
    ("INSERT", "INSERT INTO sessions (user_id, token, last_seen_at) VALUES ($1, $2, now())"),
    ("UPDATE", "UPDATE inventory SET quantity = quantity - $1 WHERE product_id = $2"),
    ("UPDATE", "UPDATE users SET last_login_at = now() WHERE id = $1"),
    ("UPDATE", "UPDATE orders SET status = $1, updated_at = now() WHERE id = $2"),
    ("DELETE", "DELETE FROM sessions WHERE last_seen_at < now() - interval '30 days'"),
]
WRITE_QUERIES = [(tag, sql) for tag, sql in QUERIES if tag in {"UPDATE", "DELETE"}]
SLOW_QUERIES = [
    "SELECT user_id, sum(total) FROM orders GROUP BY user_id ORDER BY sum(total) DESC",
    "SELECT p.category, count(*) FROM products p JOIN inventory i ON i.product_id = p.id "
    "GROUP BY p.category",
    "SELECT date_trunc('day', created_at), count(*) FROM sessions GROUP BY 1 ORDER BY 1",
]
DUP_INSERTS = [
    ("users", "INSERT INTO users (id, email) VALUES ($1, $2)"),
    ("orders", "INSERT INTO orders (id, user_id, total) VALUES ($1, $2, $3)"),
    ("products", "INSERT INTO products (id, name, price) VALUES ($1, $2, $3)"),
]
MISSING_RELATIONS = ["order_items", "user_preferences", "tmp_import", "audit_log"]
SYNTAX_ERRORS = [
    ("FORM", "SELECT * FORM orders WHERE id = $1", 10),
    ("WEHRE", "SELECT id FROM users WEHRE email = $1", 22),
    ("UPDTAE", "UPDTAE inventory SET quantity = 0 WHERE product_id = $1", 1),
]

ERROR_KINDS = ["duplicate-key", "timeout", "missing-relation", "syntax", "deadlock"]
ERROR_WEIGHTS = [30.0, 25.0, 15.0, 15.0, 15.0]

CATEGORIES = ["connection", "duration", "checkpoint", "autovacuum", "error", "warnfatal", "misc"]
CATEGORY_WEIGHTS = [20.0, 28.0, 10.0, 11.0, 10.0, 3.0, 18.0]

SHARED_BUFFERS = 16_384  # 128 MB of 8 kB pages


def pg_ts(ts: datetime) -> str:
    """Postgres %m timestamp: '2026-01-15 12:00:01.123 UTC'."""
    tzname = ts.strftime("%Z") or "UTC"
    return f"{ts:%Y-%m-%d %H:%M:%S}.{ts.microsecond // 1000:03d} {tzname}"


def session_time(delta_seconds: float) -> str:
    """Postgres session-time format: '0:09:08.621' (hours unpadded)."""
    total = max(0.0, delta_seconds)
    hours, rem = divmod(total, 3600.0)
    minutes, seconds = divmod(rem, 60.0)
    return f"{int(hours)}:{int(minutes):02d}:{seconds:06.3f}"


@dataclass
class Backend:
    """One client backend process; pid stays stable for the session."""

    pid: int
    user: str
    db: str
    host: str
    port: int
    app: str
    backend_id: int
    start: datetime


@dataclass
class Record:
    """A single log record, format-agnostic; rendered per --format."""

    severity: str
    message: str
    pid: int
    user: str = ""
    db: str = ""
    detail: str = ""
    hint: str = ""
    statement: str = ""
    sql_state: str = "00000"
    command_tag: str = ""
    backend_type: str = "client backend"
    remote_host: str = ""
    remote_port: int = 0
    session_id: str = ""
    session_start: str = ""
    line_num: int = 1
    vxid: str = ""
    txid: int = 0
    app: str = ""


def build_event_fn(cfg: RunConfig, args: argparse.Namespace) -> EventFn:
    rng = cfg.content_rng("postgres")
    fmt: str = args.format
    storm = BurstSchedule(period=600.0, length=60.0) if args.scenario == "deadlock" else None

    hosts = internal_ips(rng, 12)
    sessions: list[Backend] = []
    pending: list[Callable[[datetime], Record]] = []
    line_nums: dict[int, int] = {}
    pid_counter = rng.randint(1200, 4200)
    txid_counter = rng.randint(50_000, 90_000)
    backend_counter = 2
    postmaster_pid = rng.randint(1, 99)

    def alloc_pid() -> int:
        nonlocal pid_counter
        pid_counter += rng.randint(1, 9)
        return pid_counter

    checkpointer_pid = alloc_pid()

    def next_txid() -> int:
        nonlocal txid_counter
        txid_counter += rng.randint(1, 40)
        return txid_counter

    def next_line(pid: int) -> int:
        line_nums[pid] = line_nums.get(pid, 0) + 1
        return line_nums[pid]

    def new_backend(start: datetime) -> Backend:
        nonlocal backend_counter
        backend_counter += 1
        user = pick(rng, DB_USERS, USER_WEIGHTS)
        return Backend(
            pid=alloc_pid(),
            user=user,
            db=USER_DB[user],
            host=rng.choice(hosts),
            port=rng.randint(40_000, 64_000),
            app=rng.choice(USER_APPS[user]),
            backend_id=backend_counter,
            start=start,
        )

    def ensure_sessions(ts: datetime) -> None:
        while len(sessions) < 4:
            age = rng.uniform(60.0, 3600.0)
            sessions.append(new_backend(ts - timedelta(seconds=age)))

    def session_rec(
        b: Backend,
        severity: str,
        message: str,
        detail: str = "",
        hint: str = "",
        statement: str = "",
        sql_state: str = "00000",
        command_tag: str = "",
        txid: int = 0,
    ) -> Record:
        return Record(
            severity=severity,
            message=message,
            pid=b.pid,
            user=b.user,
            db=b.db,
            detail=detail,
            hint=hint,
            statement=statement,
            sql_state=sql_state,
            command_tag=command_tag,
            remote_host=b.host,
            remote_port=b.port,
            session_id=f"{int(b.start.timestamp()):x}.{b.pid:x}",
            session_start=pg_ts(b.start),
            line_num=next_line(b.pid),
            vxid=f"{b.backend_id}/{next_txid()}",
            txid=txid,
            app=b.app,
        )

    def bg_rec(pid: int, backend_type: str, message: str, severity: str = "LOG") -> Record:
        return Record(
            severity=severity,
            message=message,
            pid=pid,
            backend_type=backend_type,
            line_num=next_line(pid),
        )

    def connection_event(ts: datetime) -> Record:
        if len(sessions) > 4 and (len(sessions) >= 24 or rng.random() < 0.45):
            b = sessions.pop(rng.randrange(len(sessions)))
            elapsed = session_time((ts - b.start).total_seconds())
            rec = session_rec(
                b,
                "LOG",
                f"disconnection: session time: {elapsed} "
                f"user={b.user} database={b.db} host={b.host} port={b.port}",
                command_tag="idle",
            )
            line_nums.pop(b.pid, None)  # session is gone; free its line counter
            return rec
        b = new_backend(ts)
        sessions.append(b)

        def authorized(_ts: datetime) -> Record:
            return session_rec(
                b,
                "LOG",
                f"connection authorized: user={b.user} database={b.db} application_name={b.app}",
                command_tag="authentication",
            )

        pending.append(authorized)
        return Record(
            severity="LOG",
            message=f"connection received: host={b.host} port={b.port}",
            pid=b.pid,
            user="[unknown]",
            db="[unknown]",
            remote_host=b.host,
            remote_port=b.port,
            session_id=f"{int(b.start.timestamp()):x}.{b.pid:x}",
            session_start=pg_ts(b.start),
            line_num=next_line(b.pid),
        )

    def duration_event(ts: datetime) -> Record:
        b = rng.choice(sessions)
        tag, sql = rng.choice(QUERIES)
        ms = lognormal_int(rng, 420, 1.15, lo=50, hi=30_000)
        txid = next_txid() if tag != "SELECT" else 0
        return session_rec(
            b,
            "LOG",
            f"duration: {ms}.{rng.randint(0, 999):03d} ms  statement: {sql}",
            command_tag=tag,
            txid=txid,
        )

    # Checkpoint state, keyed to the virtual clock: the 'complete' record is
    # held until the claimed total duration has elapsed in event timestamps,
    # and starts are paced ~5 virtual minutes apart (checkpoint_timeout).
    ckpt_complete_msg: str | None = None
    ckpt_ready_at: datetime | None = None
    ckpt_next_start: datetime | None = None

    def checkpoint_event(ts: datetime) -> Record:
        nonlocal ckpt_complete_msg, ckpt_ready_at, ckpt_next_start
        if ckpt_ready_at is not None or (ckpt_next_start is not None and ts < ckpt_next_start):
            # A checkpoint is in flight, or the next one is not due yet:
            # emit ordinary traffic instead of an early/overlapping start.
            return duration_event(ts)
        buffers = lognormal_int(rng, 900, 0.9, lo=12, hi=SHARED_BUFFERS)
        pct = buffers / SHARED_BUFFERS * 100.0
        removed = rng.randint(0, 2)
        recycled = rng.randint(0, 4)
        write_s = rng.uniform(0.5, 30.0)
        sync_s = rng.uniform(0.001, 0.4)
        total_s = write_s + sync_s + rng.uniform(0.01, 0.3)
        files = rng.randint(4, 90)
        longest = rng.uniform(0.001, 0.05)
        distance = rng.randint(800, 90_000)
        estimate = distance + rng.randint(0, 20_000)
        ckpt_complete_msg = (
            f"checkpoint complete: wrote {buffers} buffers ({pct:.1f}%); "
            f"0 WAL file(s) added, {removed} removed, {recycled} recycled; "
            f"write={write_s:.3f} s, sync={sync_s:.3f} s, total={total_s:.3f} s; "
            f"sync files={files}, longest={longest:.3f} s, "
            f"average={sync_s / max(files, 1):.3f} s; "
            f"distance={distance} kB, estimate={estimate} kB"
        )
        ckpt_ready_at = ts + timedelta(seconds=total_s)
        ckpt_next_start = ts + timedelta(seconds=rng.uniform(270.0, 330.0))
        kind = "time" if rng.random() < 0.8 else "wal"
        return bg_rec(checkpointer_pid, "checkpointer", f"checkpoint starting: {kind}")

    def autovacuum_event(ts: datetime) -> Record:
        pid = alloc_pid()
        db = pick(rng, ["shopdb", "analytics"], [0.75, 0.25])
        table = rng.choice(TABLES)
        cpu_user = rng.uniform(0.0, 2.0)
        cpu_sys = rng.uniform(0.0, 0.4)
        elapsed = cpu_user + cpu_sys + rng.uniform(0.01, 6.0)
        usage = (
            f"system usage: CPU: user: {cpu_user:.2f} s, system: {cpu_sys:.2f} s, "
            f"elapsed: {elapsed:.2f} s"
        )
        if rng.random() < 0.7:
            msg = (
                f'automatic vacuum of table "{db}.public.{table}": '
                f"index scans: {rng.randint(0, 2)}, "
                f"pages: 0 removed, {lognormal_int(rng, 2_000, 0.8, lo=20, hi=400_000)} remain, "
                f"tuples: {lognormal_int(rng, 600, 1.0, lo=0, hi=200_000)} removed, "
                f"{lognormal_int(rng, 40_000, 1.0, lo=1_000, hi=2_000_000)} remain, "
                f"buffer usage: {lognormal_int(rng, 1_500, 0.7, lo=10, hi=500_000)} hits, "
                f"{lognormal_int(rng, 200, 0.9, lo=0, hi=100_000)} misses, "
                f"{lognormal_int(rng, 120, 0.9, lo=0, hi=100_000)} dirtied, {usage}"
            )
        else:
            msg = f'automatic analyze of table "{db}.public.{table}" {usage}'
        rec = bg_rec(pid, "autovacuum worker", msg)
        line_nums.pop(pid, None)  # one-shot worker pid; don't grow the table forever
        return rec

    def make_deadlock(ts: datetime) -> Record:
        a, b = rng.sample(sessions, 2)
        txa, txb = next_txid(), next_txid()
        tag_a, sql_a = rng.choice(WRITE_QUERIES)
        tag_b, sql_b = rng.choice(WRITE_QUERIES)
        wait_ms = f"{lognormal_int(rng, 1200, 0.6, lo=100, hi=20_000)}.{rng.randint(0, 999):03d}"

        def reciprocal(_ts: datetime) -> Record:
            return session_rec(
                b,
                "ERROR",
                "deadlock detected",
                detail=f"Process {b.pid} waits for ShareLock on transaction {txa}; "
                f"blocked by process {a.pid}.",
                hint="See server log for query details.",
                statement=sql_b,
                sql_state="40P01",
                command_tag=tag_b,
                txid=txb,
            )

        def lock_wait(_ts: datetime) -> Record:
            return session_rec(
                a,
                "LOG",
                f"process {a.pid} still waiting for ShareLock on transaction {txb} "
                f"after {wait_ms} ms",
                detail=f"Process holding the lock: {b.pid}. Wait queue: {a.pid}.",
                statement=sql_a,
                command_tag=tag_a,
                txid=txa,
            )

        pending.append(reciprocal)
        pending.append(lock_wait)
        return session_rec(
            a,
            "ERROR",
            "deadlock detected",
            detail=f"Process {a.pid} waits for ShareLock on transaction {txb}; "
            f"blocked by process {b.pid}.",
            hint="See server log for query details.",
            statement=sql_a,
            sql_state="40P01",
            command_tag=tag_a,
            txid=txa,
        )

    def error_event(ts: datetime) -> Record:
        kind = pick(rng, ERROR_KINDS, ERROR_WEIGHTS)
        if kind == "deadlock":
            return make_deadlock(ts)
        b = rng.choice(sessions)
        if kind == "duplicate-key":
            table, insert = rng.choice(DUP_INSERTS)
            return session_rec(
                b,
                "ERROR",
                f'duplicate key value violates unique constraint "{table}_pkey"',
                detail=f"Key (id)=({rng.randint(1, 99_999)}) already exists.",
                statement=insert,
                sql_state="23505",
                command_tag="INSERT",
                txid=next_txid(),
            )
        if kind == "timeout":
            return session_rec(
                b,
                "ERROR",
                "canceling statement due to statement timeout",
                statement=rng.choice(SLOW_QUERIES),
                sql_state="57014",
                command_tag="SELECT",
            )
        if kind == "missing-relation":
            rel = rng.choice(MISSING_RELATIONS)
            return session_rec(
                b,
                "ERROR",
                f'relation "{rel}" does not exist at character 15',
                statement=f"SELECT * FROM {rel} LIMIT 100",
                sql_state="42P01",
                command_tag="SELECT",
            )
        typo, stmt, pos = rng.choice(SYNTAX_ERRORS)
        return session_rec(
            b,
            "ERROR",
            f'syntax error at or near "{typo}" at character {pos}',
            statement=stmt,
            sql_state="42601",
        )

    def warnfatal_event(ts: datetime) -> Record:
        roll = rng.random()
        if roll < 0.7:
            user = pick(rng, DB_USERS, USER_WEIGHTS)
            pid = alloc_pid()
            host = rng.choice(hosts)
            port = rng.randint(40_000, 64_000)
            if roll < 0.4:
                message = f'password authentication failed for user "{user}"'
                detail = 'Connection matched pg_hba.conf line 95: "host all all 10.0.0.0/8 md5"'
                sql_state = "28P01"
            else:
                message = (
                    "remaining connection slots are reserved for "
                    "non-replication superuser connections"
                )
                detail = ""
                sql_state = "53300"
            return Record(
                severity="FATAL",
                message=message,
                pid=pid,
                user=user,
                db=USER_DB[user],
                detail=detail,
                sql_state=sql_state,
                remote_host=host,
                remote_port=port,
                session_id=f"{int(ts.timestamp()):x}.{pid:x}",
                session_start=pg_ts(ts),
                line_num=line_nums.pop(pid, 0) + 1,  # one-shot pid; never stored
            )
        b = rng.choice(sessions)
        return session_rec(
            b,
            "WARNING",
            "there is already a transaction in progress",
            sql_state="25001",
            command_tag="BEGIN",
        )

    def misc_event(ts: datetime) -> Record:
        if rng.random() < 0.92:
            b = rng.choice(sessions)
            size = lognormal_int(rng, 20_000_000, 1.0, lo=1_000_000, hi=2_000_000_000)
            return session_rec(
                b,
                "LOG",
                f'temporary file: path "base/pgsql_tmp/pgsql_tmp{b.pid}.{rng.randint(0, 8)}", '
                f"size {size}",
                statement=rng.choice(SLOW_QUERIES),
                command_tag="SELECT",
            )
        return bg_rec(
            postmaster_pid, "postmaster", "received SIGHUP, reloading configuration files"
        )

    dispatch: dict[str, Callable[[datetime], Record]] = {
        "connection": connection_event,
        "duration": duration_event,
        "checkpoint": checkpoint_event,
        "autovacuum": autovacuum_event,
        "error": error_event,
        "warnfatal": warnfatal_event,
        "misc": misc_event,
    }

    def render_stderr(ts: datetime, rec: Record) -> str:
        who = f"{rec.user}@{rec.db} " if rec.user else ""
        prefix = f"{pg_ts(ts)} [{rec.pid}] {who}"
        lines = [f"{prefix}{rec.severity}:  {rec.message}"]
        if rec.detail:
            lines.append(f"{prefix}DETAIL:  {rec.detail}")
        if rec.hint:
            lines.append(f"{prefix}HINT:  {rec.hint}")
        if rec.statement:
            lines.append(f"{prefix}STATEMENT:  {rec.statement}")
        return "\n".join(lines)

    def render_csvlog(ts: datetime, rec: Record) -> str:
        """Full fixed-width PG14+ csvlog record: always 26 columns."""
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="")
        connection_from = f"{rec.remote_host}:{rec.remote_port}" if rec.remote_host else ""
        writer.writerow(
            [
                pg_ts(ts),  # log_time
                rec.user,  # user_name
                rec.db,  # database_name
                rec.pid,  # process_id
                connection_from,  # connection_from
                rec.session_id,  # session_id
                rec.line_num,  # session_line_num
                rec.command_tag,  # command_tag
                rec.session_start,  # session_start_time
                rec.vxid,  # virtual_transaction_id
                rec.txid,  # transaction_id
                rec.severity,  # error_severity
                rec.sql_state,  # sql_state_code
                rec.message,  # message
                rec.detail,  # detail
                rec.hint,  # hint
                "",  # internal_query
                "",  # internal_query_pos
                "",  # context
                rec.statement,  # query
                "",  # query_pos
                "",  # location
                rec.app,  # application_name
                rec.backend_type,  # backend_type
                "",  # leader_pid
                0,  # query_id
            ]
        )
        return buf.getvalue()

    def render_jsonlog(ts: datetime, rec: Record) -> str:
        obj: dict[str, object] = {"timestamp": pg_ts(ts)}
        if rec.user:
            obj["user"] = rec.user
        if rec.db:
            obj["dbname"] = rec.db
        obj["pid"] = rec.pid
        if rec.remote_host:
            obj["remote_host"] = rec.remote_host
            obj["remote_port"] = rec.remote_port
        if rec.session_id:
            obj["session_id"] = rec.session_id
        obj["line_num"] = rec.line_num
        if rec.command_tag:
            obj["ps"] = rec.command_tag
        if rec.session_start:
            obj["session_start"] = rec.session_start
        if rec.vxid:
            obj["vxid"] = rec.vxid
        if rec.txid:
            obj["txid"] = rec.txid
        obj["error_severity"] = rec.severity
        obj["state_code"] = rec.sql_state
        obj["message"] = rec.message
        if rec.detail:
            obj["detail"] = rec.detail
        if rec.hint:
            obj["hint"] = rec.hint
        if rec.statement:
            obj["statement"] = rec.statement
        if rec.app:
            obj["application_name"] = rec.app
        obj["backend_type"] = rec.backend_type
        return json.dumps(obj)

    def render(ts: datetime, rec: Record) -> str:
        if fmt == "csvlog":
            return render_csvlog(ts, rec)
        if fmt == "jsonlog":
            return render_jsonlog(ts, rec)
        return render_stderr(ts, rec)

    def make_event(ts: datetime, seq: int) -> str:
        nonlocal ckpt_complete_msg, ckpt_ready_at
        if pending:
            return render(ts, pending.pop(0)(ts))
        if ckpt_ready_at is not None and ckpt_complete_msg is not None and ts >= ckpt_ready_at:
            msg = ckpt_complete_msg
            ckpt_complete_msg = None
            ckpt_ready_at = None
            return render(ts, bg_rec(checkpointer_pid, "checkpointer", msg))
        ensure_sessions(ts)
        if (
            storm is not None
            and storm.active(ts)
            and rng.random() < 0.30 + 0.55 * storm.intensity(ts)
        ):
            return render(ts, make_deadlock(ts))
        category = pick(rng, CATEGORIES, CATEGORY_WEIGHTS)
        return render(ts, dispatch[category](ts))

    return make_event


def main(argv: list[str] | None = None) -> int:
    parser = base_parser(
        "logsim-postgres",
        "Generate realistic PostgreSQL server logs (stderr prefix, csvlog, jsonlog).",
        default_rate=10.0,
    )
    parser.add_argument(
        "--format",
        choices=["stderr", "csvlog", "jsonlog"],
        default="stderr",
        help="output format (default: stderr)",
    )
    parser.add_argument(
        "--scenario",
        choices=["none", "deadlock"],
        default="none",
        help="inject recurring anomaly windows (default: none)",
    )
    args = parser.parse_args(argv)
    cfg = config_from_args(args)
    run(cfg, build_event_fn(cfg, args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
