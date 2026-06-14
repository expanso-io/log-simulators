"""Tests for logsim-retail (retail point-of-sale transactions)."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal

from log_simulators.core import BurstSchedule
from log_simulators.retail.cli import CATALOG, FIELDS, main

from .conftest import generate

_CENT = Decimal("0.01")


def _money(v: Decimal) -> Decimal:
    return v.quantize(_CENT, rounding=ROUND_HALF_UP)


def _rows(
    extra: list[str] | None = None, count: int = 200, backfill: str = "1h"
) -> list[dict[str, str]]:
    """Run in CSV mode and parse rows back into dicts."""
    lines = generate(main, count=count, extra=extra, backfill=backfill)
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    return list(reader)


class TestCsvFormat:
    def test_header_emitted_once_with_expected_columns(self) -> None:
        lines = generate(main, count=50)
        assert lines[0] == ",".join(FIELDS)
        assert all(not line.startswith("transaction_id,") for line in lines[1:])

    def test_every_row_has_constant_column_count(self) -> None:
        lines = generate(main, count=300)
        parsed = list(csv.reader(io.StringIO("\n".join(lines))))
        widths = {len(r) for r in parsed}
        assert widths == {len(FIELDS)}

    def test_no_violation_injector_columns(self) -> None:
        # the dropped error-injection feature must leave no trace
        lines = generate(main, count=200)
        assert "_error_injected" not in lines[0]
        for line in lines:
            assert "CORRUPT" not in line and "INVALID" not in line


class TestJsonFormat:
    def test_every_line_parses_with_required_keys(self) -> None:
        for line in generate(main, count=200, extra=["--format", "json"]):
            rec = json.loads(line)
            assert set(rec) == set(FIELDS)


class TestArithmetic:
    def test_money_math_is_consistent(self) -> None:
        # recompute with the same Decimal + ROUND_HALF_UP chain and require an
        # exact-to-the-cent match (locks in commercial rounding)
        for r in _rows():
            qty = int(r["quantity"])
            unit = _money(Decimal(r["unit_price"]))
            subtotal = _money(unit * qty)
            assert Decimal(r["subtotal"]) == subtotal
            disc = _money(subtotal * Decimal(r["discount_percent"]) / 100)
            assert Decimal(r["discount_amount"]) == disc
            taxable = subtotal - disc
            tax = _money(taxable * Decimal(r["tax_rate"]))
            assert Decimal(r["tax_amount"]) == tax
            assert Decimal(r["total_amount"]) == _money(taxable + tax)

    def test_no_negative_totals(self) -> None:
        assert all(Decimal(r["total_amount"]) > 0 for r in _rows(count=400))

    def test_quantities_in_range(self) -> None:
        assert all(1 <= int(r["quantity"]) <= 10 for r in _rows())


class TestEntityConsistency:
    def test_sku_maps_to_one_product_and_price(self) -> None:
        by_sku: dict[str, set[str]] = {}
        prices: dict[str, set[str]] = {}
        for r in _rows(count=500):
            by_sku.setdefault(r["sku"], set()).add(r["product_name"])
            prices.setdefault(r["sku"], set()).add(r["unit_price"])
        assert all(len(names) == 1 for names in by_sku.values())
        assert all(len(p) == 1 for p in prices.values())

    def test_skus_are_from_catalog(self) -> None:
        catalog_skus = {sku for _, _, sku, _ in CATALOG}
        assert {r["sku"] for r in _rows(count=400)} <= catalog_skus

    def test_customers_recur(self) -> None:
        ids = Counter(r["customer_id"] for r in _rows(count=600))
        members = {cid: n for cid, n in ids.items() if not cid.startswith("GUEST")}
        assert members and max(members.values()) > 1

    def test_transaction_ids_sequential(self) -> None:
        ids = [r["transaction_id"] for r in _rows(count=100)]
        assert ids == [f"TXN{i + 1:08d}" for i in range(len(ids))]

    def test_online_orders_ship_instore_use_a_lane(self) -> None:
        for r in _rows(count=400):
            if r["is_online"] == "True":
                assert r["pos_terminal"] == "WEB"
                assert r["shipping_method"] in {"standard", "express", "overnight"}
            else:
                assert r["pos_terminal"].startswith("POS")
                assert r["shipping_method"] == "pickup"


class TestRealism:
    def test_status_mostly_completed(self) -> None:
        statuses = Counter(r["transaction_status"] for r in _rows(count=600))
        assert statuses["completed"] / sum(statuses.values()) > 0.7

    def test_guests_earn_no_loyalty_points(self) -> None:
        for r in _rows(count=400):
            if r["customer_type"] == "guest":
                assert r["loyalty_points_earned"] == "0"

    def test_bestsellers_dominate(self) -> None:
        skus = Counter(r["sku"] for r in _rows(count=600))
        top = skus.most_common(3)
        assert sum(n for _, n in top) / sum(skus.values()) > 0.3


class TestDeterminism:
    def test_same_seed_identical(self) -> None:
        assert generate(main, count=80) == generate(main, count=80)

    def test_different_seed_differs(self) -> None:
        assert generate(main, count=80, seed=1) != generate(main, count=80, seed=2)


class TestScenario:
    def _split_by_window(
        self, rows: list[dict[str, str]]
    ) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        sched = BurstSchedule(period=600, length=60)
        in_win, out_win = [], []
        for r in rows:
            ts = datetime.fromisoformat(r["timestamp"])
            (in_win if sched.active(ts) else out_win).append(r)
        return in_win, out_win

    @staticmethod
    def _top3_share(rows: list[dict[str, str]]) -> float:
        c = Counter(r["sku"] for r in rows)
        return sum(n for _, n in c.most_common(3)) / len(rows)

    @staticmethod
    def _avg_discount(rows: list[dict[str, str]]) -> float:
        return sum(int(r["discount_percent"]) for r in rows) / len(rows)

    def test_flash_sale_surges_within_windows_only(self) -> None:
        # Compare in-window vs out-of-window rows of the SAME flash-sale run, so
        # the assertion does not depend on how the sample anchor aligns to the
        # burst schedule. Out-of-window rows must look like normal traffic.
        rows = _rows(extra=["--scenario", "flash-sale"], count=2000, backfill="3h")
        in_win, out_win = self._split_by_window(rows)
        assert len(in_win) > 30 and len(out_win) > 30
        assert self._top3_share(in_win) > self._top3_share(out_win)
        assert self._avg_discount(in_win) > self._avg_discount(out_win)

    def test_baseline_has_no_window_structure(self) -> None:
        rows = _rows(count=2000, backfill="3h")
        in_win, out_win = self._split_by_window(rows)
        # no scenario -> in-window and out-window discounts are ~equal
        assert abs(self._avg_discount(in_win) - self._avg_discount(out_win)) < 2.0
