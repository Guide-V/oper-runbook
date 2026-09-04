"""End-to-end against a real Atlas cluster's Performance Advisor.

The cluster must have been seeded recently with ``scripts/dev/seed_regex_workload_atlas.js``;
``make test-atlas-live`` runs the whole loop (seed, wait for ingestion, this test, cleanup).

    MONGOOPS_TEST_ATLAS_CLUSTER=cluster-free pytest -m atlas_live

Atlas credentials and MONGODB_ATLAS_PROJECT_ID come from ``.env`` as for the CLI.
"""

from __future__ import annotations

import json
import os

import pytest
from typer.testing import CliRunner

from mongoops.cli import app

CLUSTER = os.environ.get("MONGOOPS_TEST_ATLAS_CLUSTER")
SINCE = os.environ.get("MONGOOPS_TEST_ATLAS_SINCE", "1h")
NAMESPACE = "mongoops_test.customers"
EXPECTED_CATEGORIES = frozenset({"unanchored", "leading_wildcard", "negated", "case_insensitive"})

pytestmark = [
    pytest.mark.atlas_live,
    pytest.mark.skipif(not CLUSTER, reason="MONGOOPS_TEST_ATLAS_CLUSTER not set"),
]


def _run_json() -> dict:
    result = CliRunner().invoke(
        app,
        [
            "regex-finder",
            "atlas",
            "-c",
            str(CLUSTER),
            "--since",
            SINCE,
            "-n",
            NAMESPACE,
            "-f",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


def test_atlas_source_reports_seeded_regexes() -> None:
    payload = _run_json()
    findings = payload["findings"]
    assert findings, "Performance Advisor returned no regex findings for the seeded namespace"
    assert all(f["namespace"] == NAMESPACE for f in findings)

    categories = {row["category"] for row in payload["summary"]}
    missing = EXPECTED_CATEGORIES - categories
    assert not missing, f"seeded regex shapes not reported: {sorted(missing)}"

    by_pattern = {f["pattern"]: f for f in findings}
    assert by_pattern["^.*99999$"]["category"] == "leading_wildcard"
    assert by_pattern["^som"]["options"] == "i"
    assert by_pattern["record 12345$"]["plan_summary"] == "COLLSCAN"
    assert {f["command"] for f in findings} >= {"find", "aggregate", "update"}
