"""The 99_integration adapter: Blue as a controller Service, and a full round with a fake repository."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("pymongo")  # shared_services.controller imports the datastore module

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

    def load(path):
        return json.loads(path.read_text(encoding="utf-8"))

    task_id = "t-1"
    request = load(CONTRACTS / "round_request" / "examples" / "valid_round_request.json")
    request["task_id"] = task_id
    detection = request["detection"]
    labels_input = json.loads(
        (REPO_ROOT / "03_blue_role" / "dev" / "fixtures" / "inputs" / "single_fp.json")
        .read_text(encoding="utf-8")
    )
    red_proposal = load(
        CONTRACTS / "red_proposal" / "examples" / "valid_red_proposal.json"
    )
    red_proposal["task_id"] = task_id

    events = []
    labels = []
    event_ids = []
    cases = [
        *((case, "benign") for case in labels_input["false_positives"]),
        *((case, "attack") for case in labels_input["must_detect"]),
    ]
    for index, (case, label) in enumerate(cases, start=1):
        event_id = f"evt-{index}"
        event_ids.append(event_id)
        events.append(
            {
                "event_id": event_id,
                "timestamp": "2026-11-10T09:00:00Z",
                "fields": case["observed_fields"],
            }
        )
        labels.append(
            {
                "event_id": event_id,
                "label": label,
                "source": "lab_telemetry",
                "scenario_id": f"scenario-{index}",
                "review": {
                    "status": "reviewed",
                    "reviewer": "integration-test",
                    "reviewed_at": "2026-11-10T09:00:00Z",
                },
            }
        )

    telemetry = {
        "contract_version": "0.1.0",
        "evidence_id": "evidence-t-1",
        "task_id": task_id,
        "proposal_id": red_proposal["proposal_id"],
        "detection_id": detection["detection_id"],
        "source": "splunk",
        "execution": {
            "execution_id": "execution-t-1",
            "status": "succeeded",
            "operation_id": "operation-t-1",
            "approval_id": "approval-t-1",
            "started_at": "2026-11-10T09:00:00Z",
            "completed_at": "2026-11-10T09:00:01Z",
            "event_count": len(events),
            "truncated": False,
        },
        "events": events,
    }
    telemetry["content_sha256"] = hashlib.sha256(
        json.dumps(
            telemetry,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()

    label_set = {
        "contract_version": "0.1.0",
        "label_set_id": "labels-t-1",
        "label_set_version": "1",
        "dataset": request["dataset"],
        "coverage": {"total_events": len(labels), "complete": True},
        "labels": labels,
    }
    baseline = load(
        CONTRACTS / "candidate_rule" / "examples" / "valid_match_set.json"
    )
    baseline.update(
        match_set_id="baseline-t-1",
        task_id=task_id,
        role="baseline",
        detection_id=detection["detection_id"],
        rule_version=detection["rule_version"],
    )
    baseline["dataset"] = dict(request["dataset"])
    baseline["execution"]["execution_id"] = "baseline-execution-t-1"
    baseline["matches"] = [{"event_id": event_id, "index": "lab_eval"} for event_id in event_ids]
    baseline.pop("candidate_ref", None)

    candidate_rule = load(
        CONTRACTS / "candidate_rule" / "examples" / "valid_candidate_rule.json"
    )
    candidate_rule.update(task_id=task_id, detection_id=detection["detection_id"])
    candidate_matches = load(
        CONTRACTS / "candidate_rule" / "examples" / "valid_match_set.json"
    )
    candidate_matches.update(
        match_set_id="candidate-t-1",
        task_id=task_id,
        role="candidate",
        detection_id=detection["detection_id"],
        rule_version=candidate_rule["candidate_rule_version"],
        candidate_ref=candidate_rule["candidate_id"],
    )
    candidate_matches["dataset"] = dict(request["dataset"])
    candidate_matches["execution"]["execution_id"] = "candidate-execution-t-1"

    judge_result = load(
        CONTRACTS / "judge_result" / "examples" / "valid_judge_result_pass.json"
    )
    judge_result["task_id"] = task_id
    judge_result["evaluation_summary"].update(
        detection_id=detection["detection_id"],
        dataset_id=request["dataset"]["dataset_id"],
        dataset_version=request["dataset"]["dataset_version"],
        evaluation_set_id=request["dataset"]["evaluation_set_id"],
        baseline_rule_version=detection["rule_version"],
        candidate_rule_version=candidate_rule["candidate_rule_version"],
    )
    judge_result["provenance"].update(
        baseline_match_set_id=baseline["match_set_id"],
        candidate_match_set_id=candidate_matches["match_set_id"],
        baseline_execution_id=baseline["execution"]["execution_id"],
        candidate_execution_id=candidate_matches["execution"]["execution_id"],
        candidate_ref=candidate_rule["candidate_id"],
        label_set_id=label_set["label_set_id"],
        label_set_version=label_set["label_set_version"],
    )

    registry = ServiceRegistry()
    registry.register("red", static_service("red_proposal", red_proposal))
    registry.register(
        "platform_execute", static_service("telemetry_evidence", telemetry)
    )
    registry.register(
        "platform_labels", static_service("reviewed_label_set", label_set)
    )
    registry.register("platform_baseline", static_service("match_set", baseline))
    registry.register("blue", adapter.build_blue_service())
    registry.register(
        "platform_compile", static_service("candidate_rule", candidate_rule)
    )
    registry.register(
        "platform_candidate_matches",
        static_service("match_set", candidate_matches),
    )
    registry.register("judge", static_service("judge_result", judge_result))
    repo = FakeRepo()
    outcome = RoundController(repo, registry, steps=adapter.blue_round_steps()).run_round(request)
    assert outcome.outcome == "completed" and outcome.stored["blue"] == "blue_proposal"
    stored = [doc for contract, doc in repo.saved if contract == "blue_proposal"]
    assert len(stored) == 1 and stored[0]["task_id"] == task_id
    json.dumps(stored[0])  # plain JSON, storable


def test_assembled_runner_smoke_outputs_match_shared_contracts():
    import sys

    from shared_services.datastore.validation import validate

    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    path = REPO_ROOT / "99_integration" / "assembled_runs" / "run_with_real_red_and_blue.py"
    spec = importlib.util.spec_from_file_location("assembled_smoke_runner", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)

    request = json.loads(
        (CONTRACTS / "round_request" / "examples" / "valid_round_request.json")
        .read_text(encoding="utf-8")
    )
    request["task_id"] = "assembled-smoke-test"
    red = json.loads(
        (CONTRACTS / "red_proposal" / "examples" / "valid_red_proposal.json")
        .read_text(encoding="utf-8")
    )
    red["task_id"] = request["task_id"]
    evidence = runner._build_mock_evidence(request, red)
    for contract, payload in (
        ("telemetry_evidence", evidence["telemetry"]),
        ("reviewed_label_set", evidence["labels"]),
        ("match_set", evidence["baseline"]),
    ):
        result = validate(payload, contract)
        assert result is not None and result.ok, result.summary() if result else contract

    blue_input = json.loads(
        (REPO_ROOT / "03_blue_role" / "dev" / "fixtures" / "inputs" / "single_fp.json")
        .read_text(encoding="utf-8")
    )
    adapter = load_adapter("blue_service")
    proposal_result = adapter.build_blue_service().handle(blue_input)
    assert proposal_result.contract == "blue_proposal"
    candidate = {}
    candidate_result = runner._compile_mock(
        {
            "task_id": request["task_id"],
            "round_request": request,
            "blue_proposal": proposal_result.payload,
        },
        candidate,
        request,
    )
    for contract, payload in (
        ("candidate_rule", candidate_result.payload),
        ("match_set", candidate["matches"]),
        ("judge_result", runner._inconclusive_mock_judgment(request["task_id"])),
    ):
        result = validate(payload, contract)
        assert result is not None and result.ok, result.summary() if result else contract
