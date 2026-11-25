"""Test the 99_integration Blue adapter and smoke-evidence contract path."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from autosoc_blue.schemas import validation  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
CONTRACTS = REPO_ROOT / "00_shared_contracts"


def load_adapter(name):
    import sys

    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    path = REPO_ROOT / "99_integration" / "adapters" / f"{name}.py"
    if not path.is_file():
        pytest.skip("99_integration not available")
    spec = importlib.util.spec_from_file_location(f"{name}_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def adapter():
    return load_adapter("blue_service")


def test_service_returns_a_blue_proposal(adapter, fixture_input):
    result = adapter.build_blue_service().handle(fixture_input("single_fp"))
    assert result.contract == "blue_proposal"
    assert validation.validate_blue_proposal(result.payload).ok


def test_service_returns_error_response_contract_when_no_safe_edit(adapter, fixture_input):
    result = adapter.build_blue_service().handle(fixture_input("inseparable"))
    assert result.contract == "error_response"
    assert validation.validate_error_response(result.payload).ok


def test_service_with_the_mock_model_provider(adapter, fixture_input):
    result = adapter.build_blue_service(provider="mock").handle(fixture_input("multi_fp"))
    assert result.contract == "blue_proposal"


def test_blue_input_from_context_is_a_valid_blue_input(adapter):
    ctx = {"task_id": "round-x", "round_request": {"detection": {
        "detection_id": "win-encoded-powershell", "rule_version": "9.9.9", "logic_summary": "from the round"}}}
    blue_input = adapter.blue_input_from_context(ctx)
    assert validation.validate_blue_input(blue_input).ok
    assert blue_input["task_id"] == "round-x" and blue_input["detection"]["rule_version"] == "9.9.9"


def test_blue_input_from_context_maps_round_spl_to_supported_blue_format(adapter):
    round_request = json.loads(
        (CONTRACTS / "round_request" / "examples" / "valid_round_request.json")
        .read_text(encoding="utf-8")
    )
    round_request["task_id"] = "round-spl"

    blue_input = adapter.blue_input_from_context(
        {"task_id": "round-spl", "round_request": round_request}
    )

    assert validation.validate_blue_input(blue_input).ok
    assert blue_input["detection"]["rule_format"] == "spl"
    assert blue_input["detection"]["rule_text"] == round_request["detection"]["rule_text"]


def test_real_roles_and_judge_run_through_canonical_controller(monkeypatch):
    import sys
    from uuid import uuid4

    import mongomock

    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    import shared_services.datastore.repository as repository_module
    from shared_services.controller.round_controller import RoundController
    from shared_services.controller.services import WorkflowComponentAdapter
    from shared_services.datastore.repository import MongoRepository

    monkeypatch.setattr(repository_module, "MongoClient", mongomock.MongoClient)
    runner_path = (
        REPO_ROOT / "99_integration" / "assembled_runs"
        / "run_with_real_red_and_blue.py"
    )
    spec = importlib.util.spec_from_file_location("assembled_smoke_runner", runner_path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)

    red_adapter = runner._load_adapter("red_service")
    blue_adapter = runner._load_adapter("blue_service")
    judge_adapter = runner._load_adapter("judge_service")
    task_id = f"assembled-smoke-{uuid4().hex}"
    request = json.loads(
        (CONTRACTS / "round_request" / "examples" / "valid_round_request.json")
        .read_text(encoding="utf-8")
    )
    request["task_id"] = task_id
    services = runner.SimpleNamespace(
        red=WorkflowComponentAdapter(
            red_adapter.build_red_service(provider="mock"), "red_proposal"
        ),
        blue=WorkflowComponentAdapter(
            blue_adapter.build_blue_service(provider="mock"), "blue_proposal"
        ),
        platform=runner.SmokeTestPlatform(blue_adapter),
        judge=WorkflowComponentAdapter(
            judge_adapter.build_judge_service(), "judge_result"
        ),
    )
    repo = MongoRepository(db_name=f"autosoc_test_{uuid4().hex}")
    try:
        outcome = RoundController(repo, services).run_round(request)
        judge_rows = repo.find_by_task("judge_result", task_id)

        assert outcome.state == "inconclusive"
        assert {
            "red_proposal",
            "telemetry_evidence",
            "reviewed_label_set",
            "baseline_match_set",
            "blue_proposal",
            "candidate_rule",
            "candidate_match_set",
            "judge_result",
            "feedback_record",
        }.issubset(outcome.record.artifacts)
        assert judge_rows[-1]["decision"]["status"] == "INCONCLUSIVE"
    finally:
        repo.close()
