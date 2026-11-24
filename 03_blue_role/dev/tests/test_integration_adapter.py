"""The 99_integration adapter: Blue as a controller Service, and a full round with a fake repository."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("pymongo")  # shared_services.controller imports the datastore module

from autosoc_blue.schemas import validation  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]


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


class FakeRepo:
    """Just enough of MongoRepository for RoundController; validates blue_proposal like the real one."""

    def __init__(self):
        self.saved = []

    def save(self, contract, document, **_):
        if contract == "blue_proposal":
            assert validation.validate_blue_proposal(document).ok
        self.saved.append((contract, document))
        return str(len(self.saved))


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


def test_full_round_with_real_blue_and_fake_repository(adapter):
    from shared_services.controller.round_controller import RoundController
    from shared_services.controller.services import ServiceRegistry, static_service

    registry = ServiceRegistry()
    registry.register("red", static_service("red_proposal", {"task_id": "t-1"}))
    registry.register("platform_execute", static_service("telemetry_evidence", {"task_id": "t-1"}))
    registry.register("blue", adapter.build_blue_service())
    registry.register("platform_compile", static_service("candidate_rule", {"task_id": "t-1"}))
    registry.register("judge", static_service("judge_result", {"task_id": "t-1"}))
    repo = FakeRepo()
    request = {"task_id": "t-1", "detection": {"detection_id": "win-encoded-powershell",
                                               "rule_version": "3.2.0", "logic_summary": "x"}}
    outcome = RoundController(repo, registry, steps=adapter.blue_round_steps()).run_round(request)
    assert outcome.outcome == "completed" and outcome.stored["blue"] == "blue_proposal"
    stored = [doc for contract, doc in repo.saved if contract == "blue_proposal"]
    assert len(stored) == 1 and stored[0]["task_id"] == "t-1"
    json.dumps(stored[0])  # plain JSON, storable
