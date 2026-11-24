"""Test harness for shared_services using a throwaway MongoDB or mock database."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest

# tests/ -> shared_services/ -> repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

TEST_DB = f"autosoc_test_{uuid4().hex}"
TEST_MONGO_URI = os.environ.get("AUTOSOC_TEST_MONGO_URI", "mongodb://localhost:27017")


@pytest.fixture
def repo():
    from shared_services.datastore.repository import MongoRepository

    r = MongoRepository(uri=TEST_MONGO_URI, db_name=TEST_DB)
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
