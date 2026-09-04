from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def atlas_local_lines() -> tuple[str, ...]:
    """Real slow-query lines captured from an atlas-local (MongoDB 8.0) deployment."""
    return tuple(
        line
        for line in (FIXTURES / "atlas_local_slow_queries.jsonl").read_text().splitlines()
        if line.strip()
    )


@pytest.fixture(scope="session")
def legacy_lines() -> tuple[str, ...]:
    return tuple(
        line
        for line in (FIXTURES / "legacy_mongod_4_2.log").read_text().splitlines()
        if line.strip()
    )
