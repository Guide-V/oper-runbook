"""End-to-end against a live MongoDB (atlas-local recommended).

    atlas deployments setup mongoops-regex-test --type local --mdbVersion 8.0 --port 27099 --force
    MONGOOPS_TEST_MONGODB_URI="mongodb://localhost:27099/?directConnection=true" pytest -m integration

The test seeds a throw-away database, forces every op to be logged as slow, runs a set of regex
queries, then verifies the ``live`` (getLog) source reports them.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from pymongo import MongoClient
from typer.testing import CliRunner

from mongoops.cli import app
from mongoops.regex_finder.analyze import AnalyzeOptions, analyze_lines
from mongoops.regex_finder.detector import RegexCategory
from mongoops.regex_finder.sources import getlog_lines

URI = os.environ.get("MONGOOPS_TEST_MONGODB_URI")
DB = "mongoops_it"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not URI, reason="MONGOOPS_TEST_MONGODB_URI not set"),
]


@pytest.fixture(scope="module")
def seeded() -> Iterator[MongoClient]:
    client: MongoClient = MongoClient(URI, serverSelectionTimeoutMS=5000, appname="mongoops-it")
    coll = client[DB]["subscribers"]
    coll.drop()
    coll.insert_many(
        [
            {"msisdn": "66810000001", "name": "Integration One", "plan": "postpaid"},
            {"msisdn": "66820000002", "name": "Integration Two", "plan": "prepaid"},
        ]
    )
    coll.create_index("msisdn")
    client.admin.command("profile", 0, slowms=-1)  # log every operation as slow
    try:
        coll.find_one({"msisdn": {"$regex": "^6681"}})
        coll.find_one({"name": {"$regex": "integration", "$options": "i"}})
        coll.count_documents({"plan": {"$not": {"$regex": "^post"}}})
        list(coll.aggregate([{"$match": {"name": {"$regex": ".*Two$"}}}]))
        coll.find_one({"msisdn": "66810000001"})  # control: no regex
        yield client
    finally:
        client.admin.command("profile", 0, slowms=100)
        client.drop_database(DB)
        client.close()


def test_live_source_reports_seeded_regexes(seeded: MongoClient) -> None:
    assert URI is not None
    findings = tuple(
        analyze_lines(
            getlog_lines(URI), AnalyzeOptions(namespaces=frozenset({f"{DB}.subscribers"}))
        )
    )
    by_pattern = {f.pattern: f for f in findings}
    assert by_pattern["^6681"].category == RegexCategory.PREFIX
    assert "IXSCAN" in (by_pattern["^6681"].plan_summary or "")
    assert by_pattern["integration"].category == RegexCategory.CASE_INSENSITIVE
    assert by_pattern["^post"].category == RegexCategory.NEGATED
    assert by_pattern[".*Two$"].category == RegexCategory.LEADING_WILDCARD
    assert by_pattern[".*Two$"].command == "aggregate"
    assert all(f.namespace == f"{DB}.subscribers" for f in findings)


def test_cli_live_csv(seeded: MongoClient) -> None:
    assert URI is not None
    result = CliRunner().invoke(
        app, ["regex-finder", "live", "--uri", URI, "-f", "csv", "-n", f"{DB}.subscribers"]
    )
    assert result.exit_code == 0, result.output
    assert "^6681" in result.stdout
    assert "case_insensitive" in result.stdout
