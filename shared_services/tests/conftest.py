"""Test harness for shared_services. Uses a throwaway test database.

Skips the suite gracefully if MongoDB is not reachable, so it is safe in CI
without a database.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# tests/ -> shared_services/ -> repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

TEST_DB = "autosoc_test"


@pytest.fixture
def repo():
    from shared_services.datastore.repository import MongoRepository

    r = MongoRepository(db_name=TEST_DB)
    try:
        r.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MongoDB not reachable: {exc}")
    r.ensure_setup()
    yield r
    r._client.drop_database(TEST_DB)
    r.close()


@pytest.fixture
def red_proposal_example():
    path = (
        REPO_ROOT / "00_shared_contracts" / "red_proposal" / "examples" / "valid_red_proposal.json"
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}
