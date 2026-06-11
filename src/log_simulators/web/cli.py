"""Web server access/error log simulator (Apache / nginx).

Models user *sessions* walking a weighted navigation graph - the same
visitor IP, username, and user agent recur across a session's lines -
rather than emitting independent random lines. Lineage:
bacalhau-project/access-log-generator, rebuilt on the shared core.

Formats:
  combined     NCSA Combined Log Format (default; Apache/nginx access.log)
  common       NCSA Common Log Format
  json         one JSON object per line (processed/structured variant)
  nginx-error  nginx error.log lines (connection refused, timeouts, ...)

Scenarios:
  error-storm  recurring windows where 5xx responses spike (~40%)
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import datetime

from log_simulators.core import (
    USER_AGENTS,
    BurstSchedule,
    base_parser,
    config_from_args,
    lognormal_int,
    make_faker,
    ncsa_clf,
    pick,
    run,
    usernames,
    zipf_weights,
)

# page -> (weight, possible next pages)
NAV = {
    "/": (30, ["/products", "/search", "/about", "/login", "/blog"]),
    "/products": (25, ["/products/{id}", "/search", "/cart", "/"]),
    "/products/{id}": (20, ["/cart/add", "/products", "/products/{id}", "/"]),
    "/search": (12, ["/products/{id}", "/products", "/search"]),
    "/cart": (8, ["/checkout", "/products", "/"]),
    "/cart/add": (6, ["/cart", "/products", "/products/{id}"]),
    "/checkout": (4, ["/thank-you", "/cart"]),
    "/thank-you": (1, ["/", "/products"]),
    "/login": (6, ["/profile", "/", "/products"]),
    "/profile": (3, ["/", "/products", "/logout"]),
    "/logout": (1, ["/"]),
    "/about": (3, ["/", "/contact"]),
    "/contact": (2, ["/"]),
    "/blog": (4, ["/blog/{id}", "/"]),
    "/blog/{id}": (3, ["/blog", "/", "/products"]),
    "/api/v1/products": (8, ["/api/v1/products", "/api/v1/cart"]),
    "/api/v1/cart": (3, ["/api/v1/products", "/api/v1/checkout"]),
    "/api/v1/checkout": (1, ["/api/v1/products"]),
    "/admin": (1, ["/admin", "/"]),
}
ENTRY_PAGES = [
    "/",
    "/products",
    "/products/{id}",
    "/search",
    "/login",
    "/blog/{id}",
    "/api/v1/products",
]
POST_PAGES = {"/login", "/cart/add", "/checkout", "/api/v1/cart", "/api/v1/checkout"}
STATIC = ["/static/css/main.css", "/static/js/app.js", "/static/img/logo.png", "/favicon.ico"]
EXTERNAL_REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://news.ycombinator.com/",
    "-",
    "-",
    "-",
]
NGINX_ERRORS = [
    ("connect() failed (111: Connection refused) while connecting to upstream", "error"),
    (
        "upstream timed out (110: Connection timed out) while reading response header "
        "from upstream",
        "error",
    ),
    ("no live upstreams while connecting to upstream", "error"),
    ('open() "{root}{path}" failed (2: No such file or directory)', "error"),
    ('limiting requests, excess: 5.32 by zone "perip"', "warn"),
    ("client intended to send too large body: 21034218 bytes", "error"),
    ("SSL_do_handshake() failed (SSL: error:0A00006C:SSL routines::bad key share)", "crit"),
]


@dataclass
class Session:
    ip: str
    user: str
    agent: str
    page: str = "/"
    pages_left: int = 4
    referer: str = "-"
    logged_in: bool = False
    fresh: bool = True
    static_queue: list[str] = field(default_factory=list)


def _render_path(rng: random.Random, page: str) -> str:
    if page == "/products/{id}":
        return f"/products/{rng.randint(1, 500)}"
    if page == "/blog/{id}":
        return f"/blog/{rng.choice(['edge-pipelines', 'launch', 'logs-at-scale', 'roadmap'])}"
    if page == "/search":
        q = rng.choice(["laptop", "sensor", "gateway", "router", "camera", "edge"])
        return f"/search?q={q}&page={rng.randint(1, 5)}"
    return page


def build_event_fn(cfg, args):
    rng = cfg.content_rng()
    fk = make_faker(cfg.seed)
    users = usernames(fk, 80)
    user_weights = zipf_weights(len(users))
    ips = [fk.ipv4_public() for _ in range(150)]
    ip_weights = zipf_weights(len(ips), s=0.8)
    storm = BurstSchedule(period=600, length=60) if args.scenario == "error-storm" else None
    sessions: list[Session] = []
    nav_pages = list(NAV.keys())
    nav_weights = [NAV[p][0] for p in nav_pages]

    def new_session() -> Session:
        ip = pick(rng, ips, ip_weights)
        user = pick(rng, users, user_weights) if rng.random() < 0.35 else "-"
        return Session(
            ip=ip,
            user=user,
            agent=rng.choice(USER_AGENTS),
            page=pick(rng, ENTRY_PAGES, [NAV[p][0] for p in ENTRY_PAGES]),
            pages_left=max(1, int(rng.expovariate(1 / 4.0))),
            referer=rng.choice(EXTERNAL_REFERERS),
        )

    def pick_status(sess: Session, path: str, ts: datetime) -> int:
        if (
            storm is not None
            and storm.active(ts)
            and rng.random() < 0.25 + 0.5 * storm.intensity(ts)
        ):
            return rng.choice([500, 502, 503, 503, 504])
        if path.startswith("/admin"):
            return 403 if rng.random() < 0.9 else 200
        if path.startswith("/profile") and not sess.logged_in:
            return 401
        roll = rng.random()
        if roll < 0.005:
            return 500
        if roll < 0.010:
            return rng.choice([301, 302])
        if roll < 0.055:
            return 304
        if roll < 0.105 and "/products/" in path:
            return 404
        if roll < 0.115:
            return 404
        return 200

    def advance(sess: Session) -> tuple[str, str]:
        """Return (method, rendered_path) and move the session forward."""
        if sess.static_queue:
            return "GET", sess.static_queue.pop()
        page = (
            sess.page
            if sess.fresh
            else pick(
                rng,
                NAV[sess.page][1] if sess.page in NAV else nav_pages,
                None if sess.page in NAV else nav_weights,
            )
        )
        sess.fresh = False
        sess.page = page
        sess.pages_left -= 1
        if page == "/login":
            sess.logged_in = True
            if sess.user == "-":
                sess.user = pick(rng, users, user_weights)
        method = "POST" if page in POST_PAGES else "GET"
        if not page.startswith("/api/") and rng.random() < 0.3:
            sess.static_queue = rng.sample(STATIC, k=rng.randint(1, 2))
        return method, _render_path(rng, page)

    def access_line(ts: datetime, fmt: str) -> str:
        if not sessions or (len(sessions) < 60 and rng.random() < 0.25):
            sessions.append(new_session())
        sess = rng.choice(sessions)
        entering = sess.fresh
        prev_page = sess.page
        method, path = advance(sess)
        status = pick_status(sess, path, ts)
        nbytes = 0 if status == 304 else lognormal_int(rng, 2600, 0.9, lo=120, hi=900_000)
        referer = (
            sess.referer if entering else f"https://shop.example.com{_render_path(rng, prev_page)}"
        )
        if sess.pages_left <= 0 and not sess.static_queue:
            sessions.remove(sess)
        if fmt == "json":
            return json.dumps(
                {
                    "timestamp": ts.isoformat(timespec="milliseconds"),
                    "client_ip": sess.ip,
                    "user": sess.user,
                    "method": method,
                    "path": path,
                    "protocol": "HTTP/1.1",
                    "status": status,
                    "bytes": nbytes,
                    "referer": referer,
                    "user_agent": sess.agent,
                },
                separators=(", ", ": "),
            )
        ident = sess.user
        # Apache %b convention: zero-byte responses log "-", not "0".
        bytes_field = str(nbytes) if nbytes else "-"
        base = (
            f"{sess.ip} - {ident} [{ncsa_clf(ts)}] "
            f'"{method} {path} HTTP/1.1" {status} {bytes_field}'
        )
        if fmt == "common":
            return base
        return f'{base} "{referer}" "{sess.agent}"'

    def error_line(ts: datetime) -> str:
        template, level = rng.choice(NGINX_ERRORS)
        ip = pick(rng, ips, ip_weights)
        path = _render_path(rng, rng.choice(ENTRY_PAGES))
        msg = template.format(root="/usr/share/nginx/html", path=path)
        pid = 1000 + (cfg.seed or 0) % 100
        return (
            f"{ts.strftime('%Y/%m/%d %H:%M:%S')} [{level}] {pid}#{pid}: "
            f"*{rng.randint(1, 99999)} {msg}, client: {ip}, "
            f'server: shop.example.com, request: "GET {path} HTTP/1.1", '
            f'host: "shop.example.com"'
        )

    def make_event(ts: datetime, seq: int) -> str:
        if args.format == "nginx-error":
            return error_line(ts)
        return access_line(ts, args.format)

    return make_event


def main(argv: list[str] | None = None) -> int:
    parser = base_parser(
        "logsim-web",
        "Generate realistic Apache/nginx web server logs with user sessions.",
        default_rate=10.0,
    )
    parser.add_argument(
        "--format",
        choices=["combined", "common", "json", "nginx-error"],
        default="combined",
        help="output format (default: combined)",
    )
    parser.add_argument(
        "--scenario",
        choices=["none", "error-storm"],
        default="none",
        help="inject recurring anomaly windows (default: none)",
    )
    args = parser.parse_args(argv)
    cfg = config_from_args(args)
    run(cfg, build_event_fn(cfg, args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
