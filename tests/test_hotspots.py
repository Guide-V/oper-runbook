"""Golden path for "which db / collection hurts most, and what do I do first"."""

from __future__ import annotations

import json
from datetime import timedelta, timezone

import pytest

from mongoops.regex_finder.analyze import Finding
from mongoops.regex_finder.hotspots import flat_collections, headline, hotspots
from mongoops.regex_finder.remedy import Remedy
from mongoops.regex_finder.report import ReportMeta, render, summarize
from mongoops.regex_finder.summary import SummaryRow, distinct_ops, evidence, total_ms
from tests.regex_workload import workload_findings

BANGKOK = timezone(timedelta(hours=7))


@pytest.fixture(scope="module")
def findings() -> tuple[Finding, ...]:
    return workload_findings()


@pytest.fixture(scope="module")
def summary(findings: tuple[Finding, ...]) -> tuple[SummaryRow, ...]:
    return summarize(findings)


class TestPerOperationTotals:
    def test_an_operation_with_two_regexes_counts_once(self, findings: tuple[Finding, ...]) -> None:
        assert len(findings) == 27  # 6 + 6*2 + 6 + 2 + 1 usages
        assert len(distinct_ops(findings)) == 21
        assert total_ms(findings) == 6 * 905 + 6 * 289 + 6 * 144 + 2 * 50 + 2

    def test_or_shape_has_two_usages_per_op(self, summary: tuple[SummaryRow, ...]) -> None:
        names = next(r for r in summary if r.field == "name" and r.remedy is Remedy.SEARCH)
        assert (names.count, names.ops, names.total_ms) == (12, 6, 6 * 289)
        assert names.total_keys_examined == 6 * 300_000
        assert names.scanned_per_returned == round(6 * 300_000 / (6 * 22), 1)


class TestRanking:
    def test_costliest_shape_first_not_worst_category(
        self, summary: tuple[SummaryRow, ...]
    ) -> None:
        assert [(r.field, r.remedy) for r in summary] == [
            ("note", Remedy.SEARCH),  # 5.4 s, COLLSCAN 300k docs
            ("name", Remedy.SEARCH),  # 1.7 s, 300k keys
            ("name", Remedy.NORMALIZED_FIELD),  # 0.9 s: case-insensitive used to rank first
            ("ref", Remedy.BTREE_INDEX),
            ("memo", Remedy.MONITOR),
        ]
        assert summary[0].share_pct == pytest.approx(100 * 5430 / 8130, abs=0.1)

    def test_row_carries_who_when_and_how(self, summary: tuple[SummaryRow, ...]) -> None:
        top = summary[0]
        assert top.apps == "orders-api"
        assert top.first_seen.startswith("2026-10-07T07:00")
        assert top.last_seen.startswith("2026-10-07T07:05")
        assert top.effort == "new infrastructure"
        assert 'createSearchIndex("customers_note_search"' in top.fix_snippet
        assert evidence(top) == (
            "COLLSCAN on 6 of 6 op(s), 300,000 keys/docs scanned per op for 1 returned."
        )


class TestHotspots:
    def test_databases_then_collections_costliest_first(
        self, findings: tuple[Finding, ...], summary: tuple[SummaryRow, ...]
    ) -> None:
        spots = hotspots(findings, summary)
        assert [d.database for d in spots] == ["aisops", "billing"]
        aisops, billing = spots
        assert (aisops.ops, aisops.total_ms, aisops.shapes, aisops.to_fix) == (18, 8028, 3, 3)
        assert aisops.share_pct == pytest.approx(100 * 8028 / 8130, abs=0.1)
        customers = aisops.collections[0]
        assert (customers.collection, customers.main_remedy) == ("customers", Remedy.SEARCH)
        assert customers.collscan_ops == 6
        invoices = billing.collections[0]
        assert (invoices.shapes, invoices.to_fix, invoices.main_remedy) == (
            2,
            1,
            Remedy.BTREE_INDEX,
        )
        assert [c.namespace for c in flat_collections(spots)] == [
            "aisops.customers",
            "billing.invoices",
        ]

    def test_headline_says_where_and_what_first(
        self, findings: tuple[Finding, ...], summary: tuple[SummaryRow, ...]
    ) -> None:
        text = headline(findings, summary, hotspots(findings, summary))
        assert text.startswith("21 slow operation(s) used $regex, 8.1 s in total across 2 ")
        assert "aisops.customers accounts for 99% of it." in text
        assert "Biggest win: MongoDB Search for note on aisops.customers (67% of regex time)." in (
            text
        )

    def test_headline_when_nothing_needs_work(self, findings: tuple[Finding, ...]) -> None:
        quiet = tuple(f for f in findings if f.field == "memo")
        assert headline(quiet, summarize(quiet), hotspots(quiet, summarize(quiet))).endswith(
            "Nothing to fix: every shape is index-friendly or too small to matter yet."
        )
        assert headline((), (), ()) == "No $regex usage found in the analysed slow queries."


class TestRenderers:
    def test_table_summary_reads_top_down(self, findings: tuple[Finding, ...]) -> None:
        meta = ReportMeta(source="atlas", target="c", display_tz=BANGKOK)
        text = render(findings, fmt="table", view="summary", meta=meta)
        order = [
            text.index(s)
            for s in (
                "21 slow operation(s)",
                "Where the regex time goes",
                " 1. aisops.customers  note",
                " 2. aisops.customers  name",
                " 4. billing.invoices  ref",
                "$regex usage summary",
            )
        ]
        assert order == sorted(order)
        assert "last seen 2026-10-07 14:05:00 +07:00" in text  # display zone, not UTC
        assert "1 more shape(s) need no action now" in text

    def test_dashboard_has_rollup_numbered_actions_and_copyable_fixes(
        self, findings: tuple[Finding, ...]
    ) -> None:
        meta = ReportMeta(
            source="atlas",
            target="c",
            window="2026-10-07 14:00 to 15:00 +07:00 (07:00 to 08:00 UTC)",
            display_tz=BANGKOK,
            warnings=("node-0 returned 20,000 lines, the --n-logs cap",),
        )
        html = render(findings, fmt="html", view="both", meta=meta)
        assert html.index("Where the regex time goes") < html.index("What to do, biggest win")
        assert html.index("What to do, biggest win") < html.index("Shapes (5)")
        assert html.count('<button class="copy"') == 4  # one per shape that needs work
        assert "1 shape(s) need no action now" in html
        assert '<span class="chip warn"><b>warning</b>node-0 returned 20,000 lines' in html
        assert "2026-10-07 14:00:00 +07:00" in html  # findings shown in the display zone
        assert 'title="2026-10-07T07:00:00.000+00:00"' in html  # UTC kept as tooltip
        assert '<tr class="db"><td>aisops</td>' in html

    def test_json_stays_utc(self, findings: tuple[Finding, ...]) -> None:
        meta = ReportMeta(source="atlas", target="c", display_tz=BANGKOK)
        payload = json.loads(render(findings, fmt="json", view="both", meta=meta))
        assert payload["summary"][0]["last_seen"] == "2026-10-07T07:05:00.000+00:00"
        assert payload["findings"][0]["timestamp"].endswith("+00:00")
