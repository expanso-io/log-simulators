"""Structured JSON application log simulator (modern microservice logs).

Emits NDJSON - one JSON object per line - in the shape produced by modern
structured-logging libraries inside a small microservice fleet: level,
service, version, W3C trace/span ids, a monotonically increasing ``seq``
(the zero-loss-delivery proof field), HTTP context, user context with PII
(for redaction demos), and occasional multi-frame Python/Java stack traces
embedded as a JSON string field (newlines are escaped, so every event is
still exactly one line).

Format:
  ndjson  {"timestamp":"2026-01-15T12:00:00.123Z","level":"info",
           "service":"payments","trace_id":"4bf9...","seq":1234,...}

Scenarios:
  error-storm  recurring windows where one service's error rate jumps to
               ~60% with TimeoutError/ConnectionError cascades and elevated
               duration_ms (the incident demo)
  pii-leak     recurring windows where ~80% of lines carry PII fields and
               card numbers leak into the msg text (the redaction-catch demo)
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime

from log_simulators.core import (
    BurstSchedule,
    EventFn,
    RunConfig,
    base_parser,
    config_from_args,
    lognormal_int,
    make_faker,
    pick,
    rfc5424_ts,
    run,
    zipf_weights,
)

LEVELS = ["debug", "info", "warn", "error"]
LEVEL_WEIGHTS = [15, 70, 10, 5]

PII_PROBABILITY = 0.05
TRACE_JOIN_PROBABILITY = 0.20
TRACE_POOL_MAX = 50
STACK_PROBABILITY = 0.30

# service -> deployed version (stable per run, like a real fleet snapshot)
SERVICES = {
    "payments": "2.4.1",
    "auth": "1.9.3",
    "catalog": "3.1.0",
    "cart": "2.0.7",
    "shipping": "1.5.2",
    "notifications": "0.9.14",
}

MESSAGES: dict[str, dict[str, list[str]]] = {
    "payments": {
        "debug": [
            "validating card token",
            "loaded merchant config from cache",
            "computed fraud score",
            "idempotency key lookup hit",
            "serializing gateway request",
        ],
        "info": [
            "payment authorized",
            "payment captured",
            "refund issued",
            "charge created",
            "webhook delivered to merchant",
            "payout scheduled",
            "3ds challenge completed",
        ],
        "warn": [
            "gateway latency above threshold",
            "retrying declined transaction",
            "fraud score elevated, manual review queued",
            "webhook delivery retry scheduled",
            "approaching gateway rate limit",
        ],
    },
    "auth": {
        "debug": [
            "jwt signature verified",
            "session cache hit",
            "loaded jwks keys",
            "password hash computed",
            "mfa state loaded from store",
        ],
        "info": [
            "user logged in",
            "access token issued",
            "token refreshed",
            "user logged out",
            "password changed",
            "mfa challenge passed",
            "api key created",
        ],
        "warn": [
            "invalid credentials attempt",
            "token expiring soon",
            "login from new device",
            "mfa code retry",
            "session nearing absolute timeout",
        ],
    },
    "catalog": {
        "debug": [
            "search query parsed",
            "product cache warm hit",
            "inventory delta computed",
            "reindex batch assembled",
            "facet counts loaded",
        ],
        "info": [
            "product viewed",
            "search executed",
            "inventory synced",
            "product published",
            "price updated",
            "category tree rebuilt",
        ],
        "warn": [
            "search latency above slo",
            "stale inventory snapshot served",
            "image cdn slow response",
            "reindex lag growing",
            "price feed entry skipped",
        ],
    },
    "cart": {
        "debug": [
            "cart loaded from redis",
            "promo rules evaluated",
            "cart totals recomputed",
            "session cart merge previewed",
            "stock reservation checked",
        ],
        "info": [
            "item added to cart",
            "item removed from cart",
            "cart merged after login",
            "promo code applied",
            "checkout started",
            "cart converted to order",
        ],
        "warn": [
            "stock low for reserved item",
            "promo code near expiry",
            "cart size above threshold",
            "slow totals computation",
            "abandoned cart sweep delayed",
        ],
    },
    "shipping": {
        "debug": [
            "rate cards loaded",
            "carrier response parsed",
            "address normalized",
            "label payload built",
            "tracking poll scheduled",
        ],
        "info": [
            "shipment created",
            "label printed",
            "tracking updated",
            "package out for delivery",
            "package delivered",
            "carrier rates refreshed",
        ],
        "warn": [
            "carrier api latency high",
            "address verification soft fail",
            "label reprint requested",
            "tracking updates delayed",
            "rate card stale",
        ],
    },
    "notifications": {
        "debug": [
            "template rendered",
            "recipient preferences loaded",
            "provider selected",
            "payload signed",
            "delivery receipt parsed",
        ],
        "info": [
            "email queued",
            "email delivered",
            "sms sent",
            "push notification delivered",
            "digest batch dispatched",
            "webhook notification posted",
        ],
        "warn": [
            "provider latency high",
            "bounce rate elevated",
            "retry scheduled for sms",
            "push token near expiry",
            "template variable missing, default used",
        ],
    },
}

# service -> [(msg, exception type)]
ERRORS: dict[str, list[tuple[str, str]]] = {
    "payments": [
        ("payment gateway timeout", "TimeoutError"),
        ("charge declined by issuer", "CardDeclinedError"),
        ("webhook delivery failed", "ConnectionError"),
        ("ledger write conflict", "IntegrityError"),
        ("invalid currency in charge request", "ValidationError"),
    ],
    "auth": [
        ("identity provider unreachable", "ConnectionError"),
        ("token validation failed", "InvalidTokenError"),
        ("session store write timed out", "TimeoutError"),
        ("account lockout triggered", "LockoutError"),
        ("jwks refresh failed", "ConnectionError"),
    ],
    "catalog": [
        ("search cluster timeout", "TimeoutError"),
        ("inventory feed parse failure", "ValidationError"),
        ("product not found in primary store", "KeyError"),
        ("reindex job aborted", "RuntimeError"),
        ("image fetch refused", "ConnectionError"),
    ],
    "cart": [
        ("redis connection lost", "ConnectionError"),
        ("stock reservation timeout", "TimeoutError"),
        ("promo engine rejected rule", "ValidationError"),
        ("cart serialization failed", "SerializationError"),
        ("checkout handoff failed", "ConnectionError"),
    ],
    "shipping": [
        ("carrier api timeout", "TimeoutError"),
        ("address validation failed", "ValidationError"),
        ("label generation refused", "ConnectionError"),
        ("manifest upload failed", "IOError"),
        ("tracking webhook signature mismatch", "SignatureError"),
    ],
    "notifications": [
        ("smtp connection refused", "ConnectionError"),
        ("provider api timeout", "TimeoutError"),
        ("invalid recipient address", "ValidationError"),
        ("push token rejected", "TokenError"),
        ("template render failure", "RenderError"),
    ],
}

CASCADE_ERRORS = [
    ("upstream call timed out", "TimeoutError"),
    ("connection refused by downstream", "ConnectionError"),
    ("connection pool exhausted", "TimeoutError"),
    ("circuit breaker open, request shed", "ConnectionError"),
    ("deadline exceeded waiting on dependency", "TimeoutError"),
]

ERROR_DETAILS = [
    "deadline exceeded after {ms}ms",
    "retries exhausted (3/3)",
    "upstream returned no data",
    "gave up after {ms}ms",
    "caller aborted request",
]

ENDPOINTS: dict[str, list[tuple[str, str]]] = {
    "payments": [
        ("POST", "/api/v1/charge"),
        ("POST", "/api/v1/refund"),
        ("GET", "/api/v1/payments/{id}"),
        ("POST", "/api/v1/webhooks/stripe"),
        ("GET", "/api/v1/payouts"),
    ],
    "auth": [
        ("POST", "/api/v1/login"),
        ("POST", "/api/v1/token/refresh"),
        ("POST", "/api/v1/logout"),
        ("GET", "/api/v1/userinfo"),
        ("POST", "/api/v1/mfa/verify"),
    ],
    "catalog": [
        ("GET", "/api/v1/products"),
        ("GET", "/api/v1/products/{id}"),
        ("GET", "/api/v1/search"),
        ("POST", "/api/v1/products/{id}/sync"),
        ("GET", "/api/v1/categories"),
    ],
    "cart": [
        ("POST", "/api/v1/cart/items"),
        ("GET", "/api/v1/cart"),
        ("DELETE", "/api/v1/cart/items/{id}"),
        ("POST", "/api/v1/cart/checkout"),
    ],
    "shipping": [
        ("POST", "/api/v1/shipments"),
        ("GET", "/api/v1/shipments/{id}"),
        ("POST", "/api/v1/labels"),
        ("GET", "/api/v1/tracking/{id}"),
    ],
    "notifications": [
        ("POST", "/api/v1/notifications/email"),
        ("POST", "/api/v1/notifications/sms"),
        ("POST", "/api/v1/notifications/push"),
        ("GET", "/api/v1/notifications/{id}/status"),
    ],
}

LEAK_TEMPLATES = [
    "failed to process card {card}",
    "payment declined for card {card}, retry queued",
    "charge attempt with card {card} returned AVS mismatch",
    "kyc check failed for ssn {ssn}, card {card} flagged",
    "could not send receipt for card {card}, phone {phone} unreachable",
]

HEX_DIGITS = "0123456789abcdef"
POD_ALPHABET = "bcdfghjklmnpqrstvwxz2456789"  # k8s-style random suffix alphabet

PY_FRAMES = [
    ("/app/{svc}/handlers.py", "handle_request", "return await service.process(req)"),
    ("/app/{svc}/service.py", "process", "result = self.client.call(payload)"),
    ("/app/{svc}/client.py", "call", "resp = self._session.post(url, json=body, timeout=30)"),
    (
        "/usr/local/lib/python3.11/site-packages/httpx/_client.py",
        "send",
        "raise self._map_exception(exc)",
    ),
    ("/usr/local/lib/python3.11/asyncio/tasks.py", "wait_for", "raise exceptions.TimeoutError()"),
]

JAVA_EXCEPTIONS = {
    "TimeoutError": "java.net.SocketTimeoutException",
    "ConnectionError": "java.net.ConnectException",
}

JAVA_FRAMES = [
    "io.shop.{svc}.api.{cls}Controller.handle({cls}Controller.java:{n})",
    "io.shop.{svc}.core.{cls}Service.process({cls}Service.java:{n})",
    "io.shop.{svc}.client.UpstreamClient.call(UpstreamClient.java:{n})",
    "java.base/java.net.SocketInputStream.socketRead0(Native Method)",
    "java.base/java.lang.Thread.run(Thread.java:840)",
]


def _pod_host(rng: random.Random, svc: str) -> str:
    """k8s-style pod name: <service>-<replicaset hash>-<pod suffix>."""
    rs_hash = "".join(rng.choice(HEX_DIGITS) for _ in range(6))
    suffix = "".join(rng.choice(POD_ALPHABET) for _ in range(5))
    return f"{svc}-{rs_hash}-{suffix}"


def _build_stack(rng: random.Random, runtime: str, svc: str, exc_type: str, msg: str) -> str:
    """Multi-frame Python or Java stack trace, returned as one newline-joined string."""
    if runtime == "python":
        lines = ["Traceback (most recent call last):"]
        for path, func, code in PY_FRAMES[: rng.randint(3, len(PY_FRAMES))]:
            lineno = rng.randint(18, 420)
            lines.append(f'  File "{path.format(svc=svc)}", line {lineno}, in {func}')
            lines.append(f"    {code}")
        lines.append(f"{exc_type}: {msg}")
        return "\n".join(lines)
    cls = svc.capitalize()
    exc = JAVA_EXCEPTIONS.get(exc_type, f"io.shop.{svc}.{exc_type}")
    lines = [f"{exc}: {msg}"]
    for frame in JAVA_FRAMES[: rng.randint(3, len(JAVA_FRAMES))]:
        lines.append("\tat " + frame.format(svc=svc, cls=cls, n=rng.randint(20, 400)))
    return "\n".join(lines)


def build_event_fn(cfg: RunConfig, args: argparse.Namespace) -> EventFn:
    rng = cfg.content_rng()
    fk = make_faker(cfg.seed)
    service_names = list(SERVICES)
    service_weights = zipf_weights(len(service_names), s=0.5)
    hosts = {svc: _pod_host(rng, svc) for svc in service_names}
    runtimes = {svc: rng.choice(["python", "java"]) for svc in service_names}
    users = [{"id": f"u-{rng.randint(10_000, 99_999)}", "email": fk.email()} for _ in range(60)]
    user_weights = zipf_weights(len(users))
    trace_pool: list[str] = []
    storm = BurstSchedule(period=600, length=60) if args.scenario == "error-storm" else None
    leak = BurstSchedule(period=600, length=60) if args.scenario == "pii-leak" else None
    storm_service = rng.choice(service_names)

    def next_trace_id() -> str:
        """20% of events join a recent trace so pipeline join demos work."""
        if trace_pool and rng.random() < TRACE_JOIN_PROBABILITY:
            return rng.choice(trace_pool)
        tid = f"{rng.getrandbits(128):032x}"
        trace_pool.append(tid)
        if len(trace_pool) > TRACE_POOL_MAX:
            trace_pool.pop(0)
        return tid

    def pii_fields() -> tuple[dict[str, str], dict[str, str]]:
        digits = fk.credit_card_number(card_type="visa16")
        card = "-".join(digits[i : i + 4] for i in range(0, 16, 4))
        user_extra = {"ssn": fk.ssn(), "phone": fk.numerify("+1-###-555-####")}
        return user_extra, {"method": "card", "card": card}

    def pick_status(level: str, method: str) -> int:
        if level == "error":
            return rng.choice([500, 500, 502, 503, 504])
        if level == "warn":
            return pick(rng, [200, 429, 400, 404, 408], [55, 15, 12, 12, 6])
        if rng.random() < 0.03:
            return rng.choice([400, 404])
        if method == "POST" and rng.random() < 0.3:
            return 201
        if method == "DELETE" and rng.random() < 0.5:
            return 204
        return 200

    def make_event(ts: datetime, seq: int) -> str:
        svc = pick(rng, service_names, service_weights)
        level = pick(rng, LEVELS, LEVEL_WEIGHTS)
        cascade = False
        if storm is not None and storm.active(ts):
            if rng.random() < 0.5:
                svc = storm_service  # retry/cascade traffic piles onto the sick service
            if svc == storm_service:
                cascade = rng.random() < 0.3 + 0.5 * storm.intensity(ts)
        if cascade:
            level = "error"
            msg, exc_type = rng.choice(CASCADE_ERRORS)
        elif level == "error":
            msg, exc_type = rng.choice(ERRORS[svc])
        else:
            msg = rng.choice(MESSAGES[svc][level])
            exc_type = ""
        method, path = rng.choice(ENDPOINTS[svc])
        if "{id}" in path:
            path = path.replace("{id}", str(rng.randint(1_000, 99_999)))
        status = pick_status(level, method)
        if level == "error":
            duration = lognormal_int(
                rng, 5000 if cascade else 1200, 0.6 if cascade else 0.8, lo=50, hi=120_000
            )
        else:
            duration = lognormal_int(rng, 45, 0.9, lo=1, hi=30_000)
        pool_user = pick(rng, users, user_weights)
        user = dict(pool_user)  # copy: PII extras must not mutate the pool
        record: dict[str, object] = {
            "timestamp": rfc5424_ts(ts),
            "level": level,
            "service": svc,
            "version": SERVICES[svc],
            "trace_id": next_trace_id(),
            "span_id": f"{rng.getrandbits(64):016x}",
            "seq": seq,
            "msg": msg,
            "duration_ms": duration,
            "http": {"method": method, "path": path, "status": status},
            "user": user,
            "host": hosts[svc],
        }
        leaking = leak is not None and leak.active(ts) and rng.random() < 0.8
        if leaking or rng.random() < PII_PROBABILITY:
            user_extra, payment = pii_fields()
            user.update(user_extra)
            record["payment"] = payment
            if leaking:
                record["msg"] = rng.choice(LEAK_TEMPLATES).format(
                    card=payment["card"], ssn=user_extra["ssn"], phone=user_extra["phone"]
                )
        if level == "error":
            err: dict[str, object] = {
                "type": exc_type,
                "message": f"{msg}; {rng.choice(ERROR_DETAILS).format(ms=duration)}",
            }
            if rng.random() < STACK_PROBABILITY:
                err["stack"] = _build_stack(rng, runtimes[svc], svc, exc_type, msg)
            record["error"] = err
        return json.dumps(record, separators=(",", ":"))

    return make_event


def main(argv: list[str] | None = None) -> int:
    parser = base_parser(
        "logsim-app",
        "Generate structured NDJSON application logs from a microservice fleet "
        "(trace ids, seq numbers, PII fields, embedded stack traces).",
        default_rate=10.0,
    )
    parser.add_argument(
        "--scenario",
        choices=["none", "error-storm", "pii-leak"],
        default="none",
        help="inject recurring anomaly windows (default: none)",
    )
    args = parser.parse_args(argv)
    cfg = config_from_args(args)
    run(cfg, build_event_fn(cfg, args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
