"""Seeded entity pools and skewed sampling helpers.

Realism principle: the same hosts/users/IPs must recur coherently across
lines (geneve's entity-consistency rule), and popularity must be skewed
(log-synth's Zipf rule) - real traffic is never uniform-random.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from typing import TypeVar

from faker import Faker

T = TypeVar("T")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "curl/8.6.0",
    "python-requests/2.32.0",
]


def make_faker(seed: int | None) -> Faker:
    fk = Faker()
    if seed is not None:
        fk.seed_instance(seed)
    return fk


def zipf_weights(n: int, s: float = 1.1) -> list[float]:
    """Zipf-ish popularity weights: item k gets weight 1/(k+1)^s."""
    return [1.0 / (k + 1) ** s for k in range(n)]


def pick(rng: random.Random, items: list[T], weights: Sequence[float] | None = None) -> T:
    if weights is None:
        return rng.choice(items)
    return rng.choices(items, weights=weights, k=1)[0]


def public_ips(fk: Faker, n: int) -> list[str]:
    return [fk.ipv4_public() for _ in range(n)]


def internal_ips(rng: random.Random, n: int, prefix: str = "10.0") -> list[str]:
    seen: set[str] = set()
    while len(seen) < n:
        seen.add(f"{prefix}.{rng.randint(0, 254)}.{rng.randint(1, 254)}")
    return sorted(seen)


def usernames(fk: Faker, n: int) -> list[str]:
    seen: set[str] = set()
    while len(seen) < n:
        seen.add(fk.user_name())
    return sorted(seen)


def hostnames(rng: random.Random, n: int, prefix: str = "host", domain: str = "") -> list[str]:
    suffix = f".{domain}" if domain else ""
    return [f"{prefix}-{i:02d}{suffix}" for i in range(1, n + 1)]


def lognormal_int(
    rng: random.Random, median: float, sigma: float = 0.8, lo: int = 0, hi: int = 10_000_000
) -> int:
    """Long-tailed positive integer (e.g. response bytes, latency ms)."""
    import math

    value = int(rng.lognormvariate(math.log(median), sigma))
    return max(lo, min(hi, value))
