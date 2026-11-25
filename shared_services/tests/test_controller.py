"""Controller tests — relaying, persistence, and error handling."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from shared_services.controller.round_controller import (
    RoundController,
    RoundStep,
    default_round_steps,
)
from shared_services.controller.services import ServiceRegistry, static_service

REPO_ROOT = Path(__file__).resolve().parents[2]
SHARED = REPO_ROOT / "00_shared_contracts"


def _round_request(task_id="ctrl-t-1"):
    path = SHARED / "round_request" / "examples" / "valid_round_request.json"
    request = json.loads(path.read_text(encoding="utf-8"))
    request["task_id"] = task_id
    return request


def _example(folder, name, task_id=None):
    path = SHARED / folder / "examples" / name
    data = json.loads(path.read_text(encoding="utf-8"))
    data = {key: value for key, value in data.items() if not key.startswith("_")}
    if task_id is not None:
        data["task_id"] = task_id
    return data


def _telemetry_evidence(task_id, red_proposal, detection_id):
    telemetry = {
        "contract_version": "0.1.0",
        "evidence_id": f"evidence-{task_id}",
        "task_id": task_id,
        "proposal_id": red_proposal["proposal_id"],
        "detection_id": detection_id,
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
    telemetry["content_sha256"] = hashlib.sha256(
        json.dumps(
            telemetry,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return telemetry


def _full_registry(task_id, red_proposal_example, round_request):
    red_proposal = dict(red_proposal_example)
    red_proposal["task_id"] = task_id
    detection = round_request["detection"]
    dataset = round_request["dataset"]

    blue_proposal = _example("blue_proposal", "valid_blue_proposal.json", task_id)
    candidate_rule = _example("candidate_rule", "valid_candidate_rule.json", task_id)
    candidate_rule.update(
        proposal_id=blue_proposal["proposal_id"],
        detection_id=detection["detection_id"],
        base_rule_version=detection["rule_version"],
    )

    labels = _example("telemetry_evidence", "valid_reviewed_label_set.json")
    telemetry = _telemetry_evidence(task_id, red_proposal, detection["detection_id"])

    baseline = _example("candidate_rule", "valid_match_set.json", task_id)
    baseline.update(
        match_set_id=f"ms-baseline-{task_id}",
        role="baseline",
        detection_id=detection["detection_id"],
        rule_version=detection["rule_version"],
    )
    baseline["dataset"].update(dataset)
    baseline["execution"]["execution_id"] = f"exec-baseline-{task_id}"
    baseline.pop("candidate_ref", None)

    candidate_matches = _example("candidate_rule", "valid_match_set.json", task_id)
    candidate_matches.update(
        match_set_id=f"ms-candidate-{task_id}",
        role="candidate",
        detection_id=detection["detection_id"],
        rule_version=candidate_rule["candidate_rule_version"],
        candidate_ref=candidate_rule["candidate_id"],
    )
    candidate_matches["dataset"].update(dataset)
    candidate_matches["execution"]["execution_id"] = f"exec-candidate-{task_id}"

    judge_result = _example("judge_result", "valid_judge_result_pass.json", task_id)
    judge_result["evaluation_summary"].update(
        detection_id=detection["detection_id"],
        dataset_id=dataset["dataset_id"],
        dataset_version=dataset["dataset_version"],
        evaluation_set_id=dataset["evaluation_set_id"],
        baseline_rule_version=detection["rule_version"],
        candidate_rule_version=candidate_rule["candidate_rule_version"],
    )
    judge_result["provenance"].update(
        baseline_match_set_id=baseline["match_set_id"],
        candidate_match_set_id=candidate_matches["match_set_id"],
        baseline_execution_id=baseline["execution"]["execution_id"],
        candidate_execution_id=candidate_matches["execution"]["execution_id"],
        candidate_ref=candidate_rule["candidate_id"],
        label_set_id=labels["label_set_id"],
        label_set_version=labels["label_set_version"],
    )

    registry = ServiceRegistry()
    registry.register("red", static_service("red_proposal", red_proposal))
    registry.register(
        "platform_execute", static_service("telemetry_evidence", telemetry)
    )
    registry.register(
        "platform_labels", static_service("reviewed_label_set", labels)
    )
    registry.register(
        "platform_baseline", static_service("match_set", baseline)
    )
    registry.register("blue", static_service("blue_proposal", blue_proposal))
    registry.register(
        "platform_compile", static_service("candidate_rule", candidate_rule)
    )
    registry.register(
        "platform_candidate_matches",
        static_service("match_set", candidate_matches),
    )
    registry.register("judge", static_service("judge_result", judge_result))
    return registry


def test_default_steps_include_both_match_sets():
    assert [step.role for step in default_round_steps()] == [
        "red",
        "platform_execute",
        "platform_labels",
        "platform_baseline",
        "blue",
        "platform_compile",
        "platform_candidate_matches",
        "judge",
    ]


def test_full_round_completes_and_persists(repo, red_proposal_example):
    task_id = "ctrl-complete"
    request = _round_request(task_id)
    registry = _full_registry(task_id, red_proposal_example, request)
    outcome = RoundController(repo, registry).run_round(request)

    assert outcome.outcome == "completed"
    assert outcome.feedback_id
    for contract in (
        "round_request",
        "red_proposal",
        "telemetry_evidence",
        "blue_proposal",
        "candidate_rule",
        "match_set",
        "judge_result",
        "feedback_record",
    ):
        assert repo.count(contract, {"task_id": task_id}) == (
            2 if contract == "match_set" else 1
        )
    assert repo.count("reviewed_label_set", {"label_set_id": "ls-0001"}) == 1


def test_round_stops_inconclusive_on_error(repo, red_proposal_example):
    task_id = "ctrl-error"
    request = _round_request(task_id)
    registry = _full_registry(task_id, red_proposal_example, request)
    registry.register(
        "red",
        static_service(
            "error_response",
            lambda _payload: {
                "contract_version": "0.1.0",
                "error_id": "err-ctrl-1",
                "task_id": task_id,
                "category": "timeout",
                "source_component": "02_red_role",
                "message": "model gateway timed out",
                "retryable": True,
            },
        ),
    )
    outcome = RoundController(repo, registry).run_round(request)

    assert outcome.outcome == "inconclusive"
    assert "error" in outcome.reason
    assert repo.count("error_response", {"task_id": task_id}) == 1
    assert repo.count("blue_proposal", {"task_id": task_id}) == 0


def test_round_inconclusive_when_service_missing(repo):
    task_id = "ctrl-missing"
    outcome = RoundController(repo, ServiceRegistry()).run_round(
        _round_request(task_id)
    )

    assert outcome.outcome == "inconclusive"
    assert "no service wired" in outcome.reason
    assert repo.count("round_request", {"task_id": task_id}) == 1
    assert outcome.feedback_id == ""
    assert repo.count("feedback_record", {"task_id": task_id}) == 0


def test_invalid_contract_output_from_service_is_rejected(repo):
    import pytest

    from shared_services.datastore.repository import ContractViolation

    task_id = "ctrl-bad-output"
    registry = ServiceRegistry()
    registry.register(
        "red", static_service("red_proposal", lambda _payload: {"task_id": task_id})
    )
    steps = [RoundStep("red", lambda context: {"task_id": context["task_id"]})]

    with pytest.raises(ContractViolation):
        RoundController(repo, registry, steps=steps).run_round(
            _round_request(task_id)
        )


def test_red_input_is_built_from_the_contract_round_request():
    from shared_services.controller.round_controller import _red_input_from_context

    request = _round_request("ctrl-red-input")
    red_input = _red_input_from_context(
        {"task_id": "ctrl-red-input", "round_request": request}
    )

    assert red_input["prompt_version"] == request["versions"]["red_prompt"]
    assert "rule_text" not in red_input["detection"]
    assert red_input["permitted_evidence_refs"] == request["permitted_evidence_refs"]
