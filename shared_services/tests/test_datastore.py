"""Datastore tests — validation gating, round-trip, and collection mapping."""

from __future__ import annotations

import pytest

from shared_services.config import ALL_COLLECTIONS
from shared_services.datastore.repository import ContractViolation
from shared_services.datastore import schema_registry


def test_setup_creates_all_collections(repo):
    repo.ensure_setup()
    names = set(repo.db.list_collection_names())
    for coll in ALL_COLLECTIONS.values():
        assert coll in names


def test_save_and_read_valid_red_proposal(repo, red_proposal_example):
    inserted_id = repo.save("red_proposal", red_proposal_example)
    assert inserted_id
    rows = repo.find_by_task("red_proposal", red_proposal_example["task_id"])
    assert len(rows) == 1
    # returned doc is clean (no _id) and still contract-valid
    assert "_id" not in rows[0]
    assert rows[0]["proposal_id"] == red_proposal_example["proposal_id"]


def test_invalid_red_proposal_is_rejected(repo, red_proposal_example):
    bad = dict(red_proposal_example)
    bad["scenario"] = dict(bad["scenario"])
    bad["scenario"]["family"] = "arbitrary_red_team_ops"  # out of enum
    with pytest.raises(ContractViolation):
        repo.save("red_proposal", bad)
    # nothing was stored
    assert repo.count("red_proposal") == 0


def test_missing_schema_stores_unvalidated(repo):
    # judge_result has no schema yet -> stored with a warning, not rejected
    assert "judge_result" in schema_registry.missing_contracts()
    rid = repo.save("judge_result", {"task_id": "t-9", "decision": "pass"})
    assert rid
    assert repo.count("judge_result", {"task_id": "t-9"}) == 1


def test_unknown_contract_raises(repo):
    with pytest.raises(KeyError):
        repo.save("not_a_contract", {"x": 1})


def test_schema_registry_reports_known_contracts():
    available = schema_registry.available_contracts()
    assert "red_proposal" in available
    assert "error_response" in available
