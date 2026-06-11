"""Kubernetes CRI container log simulator (one node's worth of pods).

Emits the containerd CRI on-disk log format, one record per line:

    2026-01-15T12:00:00.123456789Z stdout F {"level":"info","ts":"...","msg":"request handled"}
    2026-01-15T12:00:00.234567890Z stderr F I0115 12:00:00.234567       1 controller.go:117] ...

Each record is an RFC3339Nano timestamp (exactly 9 fractional digits), a
stream (stdout|stderr), a tag (F = full line, P = partial), and the payload.
~3% of events are long lines split across 2-3 consecutive CRI records
(P, [P,] F - all on the same stream). A split line is emitted as ONE
multi-line event so its chunks stay adjacent, which is the parsing wrinkle
this simulator exists to demo: consumers must reassemble P-chains.

Note: real containerd only splits writes larger than 16 KiB; this simulator
deliberately splits at ~1 KiB chunks so the P/F mechanics show up at demo
volumes without 16 KiB lines drowning the stream.

Payload mix (one node, 8-10 pods with stable names per run):
  shop/frontend, shop/payments   Go zap-style JSON (level/ts/caller/msg/fields)
  monitoring/prometheus          zap-style JSON
  kube-system/coredns, kube-proxy  klog (I0115 12:00:00.123456       1 file.go:123] msg)
  ingress-nginx controller       nginx-ingress access-log payload

Flags:
  --pod-field   include pod/namespace metadata inside JSON app payloads

Scenarios:
  crash-loop   recurring windows where ONE app pod panics (multi-line Go
               panic stack emitted as one event), goes silent for the rest
               of the window, then logs restart lines - repeating per window
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from log_simulators.core import (
    USER_AGENTS,
    BurstSchedule,
    EventFn,
    RunConfig,
    base_parser,
    config_from_args,
    internal_ips,
    lognormal_int,
    make_faker,
    ncsa_clf,
    pick,
    rfc5424_ts,
    run,
    usernames,
    zipf_weights,
)

# kubernetes' rand.String alphabet for replicaset / pod-name suffixes
HASH_ALPHABET = "bcdfghjklmnpqrstvwxz2456789"

PARTIAL_RATE = 0.03  # fraction of events emitted as a split (P/P/F) long line

API_PATHS = [
    "/api/orders",
    "/api/products",
    "/api/cart",
    "/api/checkout",
    "/api/users/me",
    "/healthz",
    "/metrics",
    "/",
]
ERRORS = [
    "context deadline exceeded",
    "connection refused",
    "dial tcp 10.96.0.12:5432: i/o timeout",
    "EOF",
    "tls: handshake failure",
]
UPSTREAMS = ["payments", "inventory", "auth", "catalog"]
PROVIDERS = ["stripe", "adyen"]

CALLERS = {
    "frontend": [
        "server/handler.go:88",
        "cache/lru.go:142",
        "middleware/auth.go:57",
        "render/template.go:201",
    ],
    "payments": ["gateway/charge.go:203", "webhook/handler.go:64", "ledger/entry.go:119"],
    "prometheus": ["tsdb/compact.go:511", "scrape/scrape.go:1352", "storage/wal.go:874"],
}

# deployment -> level -> [(msg, field names)]
APP_MESSAGES: dict[str, dict[str, list[tuple[str, tuple[str, ...]]]]] = {
    "frontend": {
        "info": [
            ("request handled", ("path", "status", "duration_ms")),
            ("cache hit", ("key",)),
            ("session created", ("user",)),
        ],
        "warn": [
            ("slow upstream response", ("upstream", "duration_ms")),
            ("request retried", ("path", "attempt")),
        ],
        "error": [
            ("request failed", ("path", "error")),
            ("upstream unavailable", ("upstream", "error")),
        ],
    },
    "payments": {
        "info": [
            ("payment authorized", ("order_id", "amount_cents", "provider")),
            ("charge captured", ("order_id", "provider")),
            ("webhook received", ("provider", "duration_ms")),
        ],
        "warn": [
            ("provider latency high", ("provider", "duration_ms")),
            ("idempotency key reused", ("order_id",)),
        ],
        "error": [
            ("payment declined", ("order_id", "error")),
            ("provider call failed", ("provider", "error")),
        ],
    },
    "prometheus": {
        "info": [
            ("compaction completed", ("duration_ms", "blocks")),
            ("WAL checkpoint complete", ("duration_ms",)),
        ],
        "warn": [("scrape duration exceeded interval", ("target", "duration_ms"))],
        "error": [("scrape failed", ("target", "error"))],
    },
}

# klog severity -> [(source file, line, message template)]
KLOG_TEMPLATES = {
    "I": [
        ("controller.go", 117, 'syncing deployment "{ref}"'),
        ("reflector.go", 879, "Watch close - *v1.Endpoints total {n} items received"),
        ("leaderelection.go", 260, "successfully renewed lease kube-system/{lease}"),
        ("proxier.go", 853, "Syncing iptables rules, {n} rules programmed"),
        ("shared_informer.go", 313, "Caches are synced for {lease}"),
    ],
    "W": [
        (
            "reflector.go",
            458,
            "watch of *v1.ConfigMap ended with: too old resource version: {n} ({n2})",
        ),
        (
            "proxier.go",
            1421,
            "Failed to load kernel module ip_vs with modprobe; falling back to iptables",
        ),
    ],
    "E": [
        (
            "leaderelection.go",
            330,
            "error retrieving resource lock kube-system/{lease}: etcdserver: request timed out",
        ),
        ("reflector.go", 138, "Failed to watch *v1.EndpointSlice: connection refused"),
    ],
}

DEPLOY_REFS = ["shop/frontend", "shop/payments", "monitoring/prometheus"]

PANIC_FRAMES = [
    ("main.(*Server).handleOrder", "/app/server/handler.go:88"),
    ("net/http.(*ServeMux).ServeHTTP", "/usr/local/go/src/net/http/server.go:2683"),
    ("net/http.serverHandler.ServeHTTP", "/usr/local/go/src/net/http/server.go:3137"),
    ("net/http.(*conn).serve", "/usr/local/go/src/net/http/server.go:2039"),
]


@dataclass(frozen=True)
class Pod:
    namespace: str
    name: str
    app: str  # short deployment name; keys CALLERS / APP_MESSAGES for json pods
    style: str  # "json" | "klog" | "access"
    weight: float


def _build_pods(rng: random.Random) -> list[Pod]:
    """One node's pod set: stable names (deployment-rsHash-podHash) per run."""

    def h(n: int) -> str:
        return "".join(rng.choice(HASH_ALPHABET) for _ in range(n))

    pods: list[Pod] = []
    fe_rs = h(9)
    for _ in range(rng.randint(2, 3)):
        pods.append(Pod("shop", f"frontend-{fe_rs}-{h(5)}", "frontend", "json", 6.0))
    pay_rs = h(10)
    for _ in range(rng.randint(1, 2)):
        pods.append(Pod("shop", f"payments-{pay_rs}-{h(5)}", "payments", "json", 5.0))
    dns_rs = h(9)
    for _ in range(2):
        pods.append(Pod("kube-system", f"coredns-{dns_rs}-{h(5)}", "coredns", "klog", 2.0))
    pods.append(Pod("kube-system", f"kube-proxy-{h(5)}", "kube-proxy", "klog", 1.0))
    pods.append(Pod("monitoring", f"prometheus-{h(10)}-{h(5)}", "prometheus", "json", 2.0))
    pods.append(
        Pod("ingress-nginx", f"ingress-nginx-controller-{h(9)}-{h(5)}", "ingress", "access", 8.0)
    )
    return pods


def build_event_fn(cfg: RunConfig, args: argparse.Namespace) -> EventFn:
    rng = cfg.content_rng()
    fk = make_faker(cfg.seed)
    pods = _build_pods(rng)
    pod_weights = [p.weight for p in pods]
    json_pods = [p for p in pods if p.style == "json"]
    json_weights = [p.weight for p in json_pods]
    users = usernames(fk, 40)
    user_weights = zipf_weights(len(users))
    client_ips = internal_ips(rng, 60, prefix="10.244")
    ip_weights = zipf_weights(len(client_ips), s=0.8)
    path_weights = zipf_weights(len(API_PATHS))
    burst = BurstSchedule(period=600, length=60) if args.scenario == "crash-loop" else None
    crash_pod = json_pods[0]
    panicked: set[int] = set()
    restart_pending = False

    def stamp(ts: datetime) -> str:
        """RFC3339Nano (exactly 9 fractional digits), always UTC like containerd."""
        utc = ts.astimezone(timezone.utc)
        nanos = utc.microsecond * 1000 + rng.randint(0, 999)
        return f"{utc.strftime('%Y-%m-%dT%H:%M:%S')}.{nanos:09d}Z"

    def record(ts: datetime, stream: str, tag: str, payload: str) -> str:
        return f"{stamp(ts)} {stream} {tag} {payload}"

    def roll_level() -> str:
        r = rng.random()
        if r < 0.70:
            return "info"
        if r < 0.95:
            return "warn"
        return "error"

    def field_value(name: str) -> object:
        if name == "path":
            return pick(rng, API_PATHS, path_weights)
        if name == "status":
            return rng.choice([200, 200, 200, 200, 201, 204])
        if name == "duration_ms":
            return lognormal_int(rng, 35, 0.9, lo=1, hi=20_000)
        if name == "key":
            return f"cart:{rng.randint(1000, 99999)}"
        if name == "user":
            return pick(rng, users, user_weights)
        if name == "upstream":
            return rng.choice(UPSTREAMS)
        if name == "attempt":
            return rng.randint(2, 4)
        if name == "error":
            return rng.choice(ERRORS)
        if name == "order_id":
            return f"ord_{rng.randrange(16**8):08x}"
        if name == "amount_cents":
            return rng.randint(199, 99_999)
        if name == "provider":
            return rng.choice(PROVIDERS)
        if name == "target":
            return f"http://{pick(rng, client_ips, ip_weights)}:9100/metrics"
        if name == "blocks":
            return rng.randint(1, 12)
        raise ValueError(name)

    def json_payload(
        pod: Pod, ts: datetime, level: str, msg: str, fields: dict[str, object]
    ) -> str:
        doc: dict[str, object] = {
            "level": level,
            "ts": rfc5424_ts(ts.astimezone(timezone.utc)),
            "caller": rng.choice(CALLERS[pod.app]),
            "msg": msg,
            **fields,
        }
        if args.pod_field:
            doc["pod"] = pod.name
            doc["namespace"] = pod.namespace
        return json.dumps(doc, separators=(",", ":"))

    def json_event(pod: Pod, ts: datetime) -> str:
        level = roll_level()
        msg, names = rng.choice(APP_MESSAGES[pod.app][level])
        fields = {n: field_value(n) for n in names}
        stream = "stdout" if level == "info" else "stderr"
        return record(ts, stream, "F", json_payload(pod, ts, level, msg, fields))

    def klog_event(pod: Pod, ts: datetime) -> str:
        sev = {"info": "I", "warn": "W", "error": "E"}[roll_level()]
        src, lineno, template = rng.choice(KLOG_TEMPLATES[sev])
        msg = template.format(
            ref=rng.choice(DEPLOY_REFS),
            lease=pod.app,
            n=rng.randint(3, 4000),
            n2=rng.randint(100_000, 999_999),
        )
        utc = ts.astimezone(timezone.utc)
        head = (
            f"{sev}{utc.month:02d}{utc.day:02d} "
            f"{utc.strftime('%H:%M:%S')}.{utc.microsecond:06d}       1 "
        )
        return record(ts, "stderr", "F", f"{head}{src}:{lineno}] {msg}")

    def access_event(pod: Pod, ts: datetime) -> str:
        ip = pick(rng, client_ips, ip_weights)
        method = rng.choices(["GET", "POST", "PUT", "DELETE"], weights=[80, 14, 4, 2])[0]
        path = pick(rng, API_PATHS, path_weights)
        status = rng.choices([200, 201, 204, 304, 404, 499, 502], weights=[78, 4, 3, 6, 5, 2, 2])[0]
        nbytes = 0 if status == 304 else lognormal_int(rng, 1800, 0.9, lo=0, hi=500_000)
        rt = lognormal_int(rng, 12, 0.9, lo=1, hi=30_000) / 1000
        upstream_rt = round(max(0.001, rt - 0.001), 3)
        upstream = f"{pick(rng, client_ips, ip_weights)}:8080"
        req_id = f"{rng.getrandbits(64):016x}"
        payload = (
            f'{ip} - - [{ncsa_clf(ts)}] "{method} {path} HTTP/1.1" {status} {nbytes} '
            f'"-" "{rng.choice(USER_AGENTS)}" {rng.randint(180, 900)} {rt:.3f} '
            f"[shop-frontend-80] [] {upstream} {nbytes} {upstream_rt:.3f} {status} {req_id}"
        )
        return record(ts, "stdout", "F", payload)

    def pick_pod(exclude_crash: bool) -> Pod:
        pod = pick(rng, pods, pod_weights)
        while exclude_crash and pod is crash_pod:
            pod = pick(rng, pods, pod_weights)
        return pod

    def partial_event(ts: datetime, exclude_crash: bool) -> str:
        """A long JSON line split into 2-3 CRI records: P, [P,] F (one stream)."""
        pod = pick(rng, json_pods, json_weights)
        while exclude_crash and pod is crash_pod:
            pod = pick(rng, json_pods, json_weights)
        body = "".join(rng.choices("0123456789abcdef", k=rng.randint(600, 1400)))
        payload = json_payload(
            pod, ts, "info", "request body accepted", {"path": field_value("path"), "body": body}
        )
        n_chunks = rng.randint(2, 3)
        cuts = sorted(rng.sample(range(40, len(payload) - 40), n_chunks - 1))
        lines: list[str] = []
        cur, prev = ts, 0
        for i, cut in enumerate([*cuts, len(payload)]):
            tag = "F" if i == n_chunks - 1 else "P"
            lines.append(record(cur, "stdout", tag, payload[prev:cut]))
            cur += timedelta(microseconds=rng.randint(80, 900))
            prev = cut
        return "\n".join(lines)

    def panic_event(ts: datetime) -> str:
        """Multi-line Go panic from the crashing pod; every line its own F record."""
        lines = [
            "panic: runtime error: invalid memory address or nil pointer dereference",
            f"[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 "
            f"pc=0x{rng.randrange(16**6):x}]",
            f"goroutine {rng.randint(1, 200)} [running]:",
        ]
        for func, src in PANIC_FRAMES:
            ptr = f"0xc{rng.randrange(16**9):09x}"
            iface = f"0x{rng.randrange(16**6):06x}"
            lines.append(f"{func}({ptr}, {{{iface}, 0xc{rng.randrange(16**9):09x}}})")
            lines.append(f"\t{src} +0x{rng.randrange(4096):x}")
        lines.append("created by net/http.(*Server).Serve in goroutine 1")
        lines.append("\t/usr/local/go/src/net/http/server.go:3285 +0x4b4")
        out: list[str] = []
        cur = ts
        for text in lines:
            out.append(record(cur, "stderr", "F", text))
            cur += timedelta(microseconds=rng.randint(50, 400))
        return "\n".join(out)

    def restart_event(ts: datetime) -> str:
        """Container restarted by kubelet: startup banner from the crashed pod."""
        first = json_payload(
            crash_pod, ts, "info", "configuration loaded", {"config": "/etc/app/config.yaml"}
        )
        ts2 = ts + timedelta(microseconds=rng.randint(200, 2000))
        second = json_payload(crash_pod, ts2, "info", "Starting server on :8080", {})
        return record(ts, "stdout", "F", first) + "\n" + record(ts2, "stdout", "F", second)

    def make_event(ts: datetime, seq: int) -> str | None:
        nonlocal restart_pending
        crash_active = False
        if burst is not None:
            if burst.active(ts):
                crash_active = True
                window = int(ts.timestamp() // burst.period)
                if window not in panicked:
                    panicked.add(window)
                    restart_pending = True
                    return panic_event(ts)
                # crashed pod stays silent for the rest of the window
            elif restart_pending:
                restart_pending = False
                return restart_event(ts)
        if rng.random() < PARTIAL_RATE:
            return partial_event(ts, exclude_crash=crash_active)
        pod = pick_pod(exclude_crash=crash_active)
        if pod.style == "json":
            return json_event(pod, ts)
        if pod.style == "klog":
            return klog_event(pod, ts)
        return access_event(pod, ts)

    return make_event


def main(argv: list[str] | None = None) -> int:
    parser = base_parser(
        "logsim-k8s",
        "Generate Kubernetes CRI/containerd container logs for one node's pods.",
        default_rate=10.0,
    )
    parser.add_argument(
        "--pod-field",
        action="store_true",
        help="include pod and namespace fields inside JSON app payloads",
    )
    parser.add_argument(
        "--scenario",
        choices=["none", "crash-loop"],
        default="none",
        help="inject recurring anomaly windows (default: none)",
    )
    args = parser.parse_args(argv)
    cfg = config_from_args(args)
    run(cfg, build_event_fn(cfg, args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
