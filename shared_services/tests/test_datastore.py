"""Datastore tests — validation gating, round-trip, and collection mapping."""

from __future__ import annotations

import hashlib
import json

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


def test_auxiliary_round_record_without_schema_stores_unvalidated(repo):
    # Audit and round records are auxiliary Mongo documents, not shared contracts.
    assert {"round_record", "audit_record"} <= set(ALL_COLLECTIONS)
    assert schema_registry.load_schema("round_record") is None
    round_id = repo.save("round_record", {"task_id": "t-9", "state": "created"})
    audit_id = repo.save("audit_record", {"task_id": "t-9", "event_type": "test_event"})
    assert round_id and audit_id
    assert repo.count("round_record", {"task_id": "t-9"}) == 1
    assert repo.count("audit_record", {"task_id": "t-9"}) == 1


def test_unknown_contract_raises(repo):
    with pytest.raises(KeyError):
        repo.save("not_a_contract", {"x": 1})


def test_schema_registry_reports_known_contracts():
    available = schema_registry.available_contracts()
    assert "red_proposal" in available
    assert "error_response" in available
    assert "match_set" in available
    assert "reviewed_label_set" in available
    assert "telemetry_evidence" in available
    assert "telemetry_evidence" not in schema_registry.temporary_contracts()
    assert "judge_result" not in schema_registry.missing_contracts()


def test_new_storage_schemas_validate_examples_without_mongo():
    from shared_services.datastore.validation import validate

    cases = (
        ("match_set", "00_shared_contracts/candidate_rule/examples/valid_match_set.json"),
        (
            "reviewed_label_set",
            "00_shared_contracts/telemetry_evidence/examples/valid_reviewed_label_set.json",
        ),
    )
    for contract, path in cases:
        result = validate(_valid_example(path), contract)
        assert result is not None and result.ok, f"{contract}: {result}"

    telemetry = _valid_telemetry_evidence("telemetry-schema-test")
    result = validate(telemetry, "telemetry_evidence")
    assert result is not None and result.ok

    invalid = dict(telemetry, source="not-splunk")
    result = validate(invalid, "telemetry_evidence")
    assert result is not None and not result.ok


def _valid_round_request():
    path = schema_registry.SHARED / "round_request" / "examples" / "valid_round_request.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_valid_round_request_with_evidence_refs_is_stored(repo):
    # permitted_evidence_refs uses a $ref by $id; this needs the schema registry.
    request = _valid_round_request()
    assert request["permitted_evidence_refs"]
    assert repo.save("round_request", request)
    assert repo.count("round_request", {"task_id": request["task_id"]}) == 1


def test_round_request_with_bad_evidence_ref_is_rejected(repo):
    request = _valid_round_request()
    request["permitted_evidence_refs"] = [{"evidence_id": "e1", "evidence_type": "model_claim"}]
    with pytest.raises(ContractViolation):
        repo.save("round_request", request)
    assert repo.count("round_request") == 0


def test_old_shaped_round_request_is_rejected(repo):
    old = {"task_id": "t", "detection": {"detection_id": "d", "rule_version": "1", "logic_summary": "x"},
           "prompt_version": "red-system@0.1.0"}
    with pytest.raises(ContractViolation):
        repo.save("round_request", old)


def test_judge_result_schema_is_enforced(repo):
    result = _valid_example("00_shared_contracts/judge_result/examples/valid_judge_result_pass.json")
    assert repo.save("judge_result", result)
    assert repo.count("judge_result", {"task_id": result["task_id"]}) == 1

    invalid = dict(result)
    invalid["task_id"] = ""
    with pytest.raises(ContractViolation):
        repo.save("judge_result", invalid)


def _valid_example(relative_path):
    path = schema_registry.REPO_ROOT / relative_path
    data = json.loads(path.read_text(encoding="utf-8"))
    return {key: value for key, value in data.items() if not key.startswith("_")}


def test_match_set_and_reviewed_label_set_are_mapped_validated_and_readable(repo):
    match_set = _valid_example("00_shared_contracts/candidate_rule/examples/valid_match_set.json")
    labels = _valid_example("00_shared_contracts/telemetry_evidence/examples/valid_reviewed_label_set.json")

    assert repo.save("match_set", match_set)
    assert repo.save("reviewed_label_set", labels)
    assert repo.count("match_set", {"task_id": match_set["task_id"]}) == 1
    assert repo.count("reviewed_label_set", {"label_set_id": labels["label_set_id"]}) == 1
    assert "match_set" in schema_registry.available_contracts()
    assert "reviewed_label_set" in schema_registry.available_contracts()


@pytest.mark.parametrize("contract,example_path,mutate", [
    (
        "match_set",
        "00_shared_contracts/candidate_rule/examples/valid_match_set.json",
        lambda document: document.update(role="not-a-role"),
    ),
    (
        "reviewed_label_set",
        "00_shared_contracts/telemetry_evidence/examples/valid_reviewed_label_set.json",
        lambda document: document["labels"][0].update(label="not-a-label"),
    ),
])
def test_invalid_match_set_and_label_set_are_rejected(repo, contract, example_path, mutate):
    document = _valid_example(example_path)
    mutate(document)
    with pytest.raises(ContractViolation):
        repo.save(contract, document)
    assert repo.count(contract) == 0


def test_telemetry_evidence_shared_schema_validates_writes(repo):
    evidence = _valid_telemetry_evidence("telemetry-db-test")
    assert repo.save("telemetry_evidence", evidence)
    assert repo.count("telemetry_evidence", {"task_id": evidence["task_id"]}) == 1

    invalid = dict(evidence, source="not-splunk")
    with pytest.raises(ContractViolation):
        repo.save("telemetry_evidence", invalid)


def _valid_telemetry_evidence(task_id):
    evidence = {
        "contract_version": "0.1.0",
        "evidence_id": f"evidence-{task_id}",
        "task_id": task_id,
        "proposal_id": "proposal-telemetry-test",
        "detection_id": "det-telemetry-test",
        "source": "splunk",
        "execution": {
            "execution_id": f"execution-{task_id}",
            "status": "succeeded",
            "operation_id": f"operation-{task_id}",
            "approval_id": f"approval-{task_id}",
            "started_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:00:01Z",
            "event_count": 0,
            "truncated": False,
        },
        "events": [],
    }
    evidence["content_sha256"] = hashlib.sha256(
        json.dumps(
            evidence,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return evidence
