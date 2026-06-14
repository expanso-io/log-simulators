"""Retail point-of-sale transaction simulator (CSV or JSON).

Emits structured retail transaction records - the tabular/file-ingestion
counterpart to the line-oriented log tools. Lineage:
expanso-cluster/scripts/generate-csv-files.py, rebuilt on the shared core.
The original's schema-violation injector is intentionally NOT ported - this
generator emits clean, well-formed records only.

What makes it realistic rather than random:
  - a fixed product catalog where each product has a STABLE sku and list
    price (a "Laptop Pro 15" is always ELEC-1042 at $1299.00)
  - Zipf product popularity (a few best-sellers dominate the receipts)
  - recurring customers with stable ids and loyalty tier
  - per-region sales tax; online orders ship, in-store orders use a POS lane

Formats:
  csv      header row once, then one transaction per row (default)
  json     one JSON object per line (NDJSON)

Scenarios:
  flash-sale   recurring windows where a few promoted SKUs surge in volume,
               basket size, and discount depth (a sales-event spike to catch
               at the edge - NOT a data-corruption injector)
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import random
from dataclasses import dataclass
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal

from log_simulators.core import (
    BurstSchedule,
    RunConfig,
    base_parser,
    config_from_args,
    pick,
    run,
    zipf_weights,
)
from log_simulators.core.runner import EventFn

# name, category, sku, list price (stable per product)
CATALOG: list[tuple[str, str, str, float]] = [
    ("Laptop Pro 15", "Electronics", "ELEC-1042", 1299.00),
    ("Monitor 27in 4K", "Electronics", "ELEC-1108", 449.00),
    ("Wireless Mouse", "Electronics", "ELEC-2031", 24.99),
    ("USB-C Cable 2m", "Electronics", "ELEC-2076", 12.99),
    ("Mechanical Keyboard", "Electronics", "ELEC-2090", 89.99),
    ("Coffee Maker", "Appliances", "APPL-3011", 79.99),
    ("Blender Pro", "Appliances", "APPL-3042", 119.00),
    ("Air Fryer XL", "Appliances", "APPL-3055", 99.99),
    ("Desk Chair Ergonomic", "Furniture", "FURN-4007", 249.00),
    ("Standing Desk", "Furniture", "FURN-4019", 399.00),
    ("Running Shoes", "Apparel", "APRL-5003", 109.99),
    ("Winter Jacket", "Apparel", "APRL-5024", 159.00),
    ("Cotton T-Shirt", "Apparel", "APRL-5061", 19.99),
    ("Yoga Mat", "Sports", "SPRT-6002", 34.99),
    ("Dumbbell Set 20kg", "Sports", "SPRT-6018", 89.00),
    ("Water Bottle 1L", "Sports", "SPRT-6044", 14.99),
    ("Office Notebook", "Stationery", "STAT-7005", 6.99),
    ("Pen Set Premium", "Stationery", "STAT-7022", 29.99),
]

# id, name, region, sales-tax rate
STORES: list[tuple[str, str, str, float]] = [
    ("STR001", "Downtown Flagship", "North", 0.0875),
    ("STR002", "Westside Mall", "West", 0.0925),
    ("STR003", "East Bay Center", "East", 0.0625),
    ("STR004", "South Plaza", "South", 0.0700),
    ("STR005", "Central Market", "Central", 0.0800),
]

_CENT = Decimal("0.01")


def _money(value: Decimal) -> Decimal:
    """Round to cents using commercial round-half-up (not banker's rounding)."""
    return value.quantize(_CENT, rounding=ROUND_HALF_UP)


PAYMENT_METHODS = ["credit_card", "credit_card", "debit_card", "cash", "mobile_pay", "gift_card"]
CUSTOMER_TYPES = ["regular", "regular", "regular", "member", "member", "premium"]
DISCOUNTS = [0, 0, 0, 0, 0, 5, 10, 15, 20]
STATUSES = ["completed", "refunded", "cancelled", "pending"]
STATUS_WEIGHTS = [85, 5, 3, 7]

FIELDS = [
    "transaction_id",
    "timestamp",
    "store_id",
    "store_name",
    "region",
    "product_name",
    "product_category",
    "sku",
    "quantity",
    "unit_price",
    "subtotal",
    "tax_rate",
    "tax_amount",
    "discount_percent",
    "discount_amount",
    "total_amount",
    "payment_method",
    "customer_id",
    "customer_type",
    "transaction_status",
    "employee_id",
    "pos_terminal",
    "loyalty_points_earned",
    "is_online",
    "shipping_method",
]


@dataclass(frozen=True)
class Customer:
    id: str
    type: str


def _build_customers(rng: random.Random, n: int) -> list[Customer]:
    seen: set[str] = set()
    customers: list[Customer] = []
    while len(customers) < n:
        cid = f"CUST{rng.randint(10000, 99999)}"
        if cid in seen:
            continue
        seen.add(cid)
        customers.append(Customer(cid, pick(rng, CUSTOMER_TYPES)))
    return customers


def build_event_fn(cfg: RunConfig, args: argparse.Namespace) -> EventFn:
    rng = cfg.content_rng()
    product_weights = zipf_weights(len(CATALOG), s=0.9)
    store_weights = zipf_weights(len(STORES), s=0.4)
    customers = _build_customers(rng, 200)
    customer_weights = zipf_weights(len(customers), s=0.7)
    # stable cashier + POS lane pools per store
    employees = {s[0]: [f"EMP{rng.randint(100, 999)}" for _ in range(8)] for s in STORES}
    lanes = {s[0]: [f"POS{i:02d}" for i in range(1, rng.randint(6, 12))] for s in STORES}

    sale = BurstSchedule(period=600, length=60) if args.scenario == "flash-sale" else None
    promo_idx = rng.sample(range(len(CATALOG)), k=3) if sale else []

    header_pending = args.format == "csv"

    def transaction(ts: datetime, seq: int) -> dict[str, object]:
        on_sale = sale is not None and sale.active(ts)
        if on_sale and rng.random() < 0.4 + 0.4 * sale.intensity(ts):  # type: ignore[union-attr]
            name, category, sku, price = CATALOG[rng.choice(promo_idx)]
        else:
            name, category, sku, price = pick(rng, CATALOG, product_weights)

        store_id, store_name, region, tax_rate = pick(rng, STORES, store_weights)

        if rng.random() < 0.30:
            customer = Customer(f"GUEST{rng.randint(100000, 999999)}", "guest")
        else:
            customer = pick(rng, customers, customer_weights)

        if on_sale:
            quantity = rng.randint(1, 6)
            discount_pct = pick(rng, [10, 15, 20, 25])
        else:
            quantity = min(10, 1 + int(rng.expovariate(1.1)))
            discount_pct = rng.choice(DISCOUNTS)

        # Money is computed with Decimal + ROUND_HALF_UP (commercial rounding),
        # not float round() (banker's rounding), so receipts match how a real
        # POS / accounting system totals them.
        unit_price = _money(Decimal(str(price)))
        subtotal = _money(unit_price * quantity)
        discount_amount = _money(subtotal * Decimal(discount_pct) / 100)
        taxable = subtotal - discount_amount
        tax_amount = _money(taxable * Decimal(str(tax_rate)))
        total = _money(taxable + tax_amount)

        is_online = rng.random() < 0.35
        if is_online:
            pos_terminal = "WEB"
            shipping = pick(rng, ["standard", "standard", "express", "overnight"])
        else:
            pos_terminal = rng.choice(lanes[store_id])
            shipping = "pickup"

        points = int(total) if customer.type in ("member", "premium") else 0
        return {
            "transaction_id": f"TXN{seq + 1:08d}",
            "timestamp": ts.isoformat(timespec="seconds"),
            "store_id": store_id,
            "store_name": store_name,
            "region": region,
            "product_name": name,
            "product_category": category,
            "sku": sku,
            "quantity": quantity,
            "unit_price": f"{unit_price:.2f}",
            "subtotal": f"{subtotal:.2f}",
            "tax_rate": f"{tax_rate:.4f}",
            "tax_amount": f"{tax_amount:.2f}",
            "discount_percent": discount_pct,
            "discount_amount": f"{discount_amount:.2f}",
            "total_amount": f"{total:.2f}",
            "payment_method": pick(rng, PAYMENT_METHODS),
            "customer_id": customer.id,
            "customer_type": customer.type,
            "transaction_status": rng.choices(STATUSES, weights=STATUS_WEIGHTS, k=1)[0],
            "employee_id": "WEB" if is_online else rng.choice(employees[store_id]),
            "pos_terminal": pos_terminal,
            "loyalty_points_earned": points,
            "is_online": is_online,
            "shipping_method": shipping,
        }

    def make_event(ts: datetime, seq: int) -> str:
        nonlocal header_pending
        rec = transaction(ts, seq)
        if args.format == "json":
            return json.dumps(rec, separators=(",", ":"))
        buf = io.StringIO()
        csv.writer(buf, lineterminator="").writerow([rec[f] for f in FIELDS])
        row = buf.getvalue()
        if header_pending:
            header_pending = False
            return ",".join(FIELDS) + "\n" + row
        return row

    return make_event


def main(argv: list[str] | None = None) -> int:
    parser = base_parser(
        "logsim-retail",
        "Generate clean retail point-of-sale transaction records (CSV or JSON).",
        default_rate=10.0,
    )
    parser.add_argument(
        "--format",
        choices=["csv", "json"],
        default="csv",
        help="output format (default: csv)",
    )
    parser.add_argument(
        "--scenario",
        choices=["none", "flash-sale"],
        default="none",
        help="inject recurring benign sales-spike windows (default: none)",
    )
    args = parser.parse_args(argv)
    cfg = config_from_args(args)
    run(cfg, build_event_fn(cfg, args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
