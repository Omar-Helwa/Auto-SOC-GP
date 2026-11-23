"""Controller tests — relaying, persistence, and error handling."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from shared_services.controller.round_controller import RoundController, RoundStep
from shared_services.controller.services import ServiceRegistry, static_service


def _round_request(task_id="ctrl-t-1"):
    return {
        "task_id": task_id,
        "detection": {"detection_id": "d", "rule_version": "1.0.0", "logic_summary": "x"},
        "benign_constraints": {
            "allowed_scenario_families": ["admin_automation"],
            "max_workflow_steps": 3,
            "allowed_actions": ["script_execution"],
        },
        "prompt_version": "red-system@0.1.0",
    }


def _full_registry(task_id, red_proposal_example):
    red_proposal_example = dict(red_proposal_example)
    red_proposal_example["task_id"] = task_id
    contracts = Path(__file__).resolve().parents[2] / "00_shared_contracts"
    blue_proposal = json.loads(
        (contracts / "blue_proposal" / "examples" / "valid_blue_proposal.json").read_text(
            encoding="utf-8"
        )
    )
    blue_proposal["task_id"] = task_id
    candidate_rule = json.loads(
        (contracts / "candidate_rule" / "examples" / "valid_candidate_rule.json").read_text(
            encoding="utf-8"
        )
    )
    candidate_rule.update(
        task_id=task_id,
        proposal_id=blue_proposal["proposal_id"],
        detection_id=blue_proposal["detection_under_test"]["detection_id"],
    )
    telemetry = {
        "contract_version": "0.1.0",
        "evidence_id": f"evidence-{task_id}",
        "task_id": task_id,
        "proposal_id": red_proposal_example["proposal_id"],
        "detection_id": red_proposal_example["detection_under_test"]["detection_id"],
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
    reg = ServiceRegistry()
    reg.register("red", static_service("red_proposal", lambda _p: red_proposal_example))
    reg.register("platform_execute", static_service(
        "telemetry_evidence", lambda _p: telemetry))
    reg.register("blue", static_service("blue_proposal", lambda _p: blue_proposal))
    reg.register("platform_compile", static_service(
        "candidate_rule", lambda _p: candidate_rule))
    reg.register("judge", static_service(
        "judge_result", lambda _p: {"task_id": task_id, "decision": "pass"}))
    return reg


def test_full_round_completes_and_persists(repo, red_proposal_example):
    task_id = "ctrl-complete"
    reg = _full_registry(task_id, red_proposal_example)
    outcome = RoundController(repo, reg).run_round(_round_request(task_id))

    assert outcome.outcome == "completed"
    assert outcome.feedback_id
    # every expected collection has the round's document
    for contract in ("round_request", "red_proposal", "telemetry_evidence",
                     "blue_proposal", "candidate_rule", "judge_result", "feedback_record"):
        assert repo.count(contract, {"task_id": task_id}) == 1


def test_round_stops_inconclusive_on_error(repo, red_proposal_example):
    task_id = "ctrl-error"
    reg = _full_registry(task_id, red_proposal_example)
    # Replace red with a service that returns an error_response
    reg.register("red", static_service("error_response", lambda _p: {
        "contract_version": "0.1.0",
        "error_id": "err-ctrl-1",
        "task_id": task_id,
        "category": "timeout",
        "source_component": "02_red_role",
        "message": "model gateway timed out",
        "retryable": True,
    }))
    outcome = RoundController(repo, reg).run_round(_round_request(task_id))

    assert outcome.outcome == "inconclusive"
    assert "error" in outcome.reason
    # error stored, but downstream steps did not run
    assert repo.count("error_response", {"task_id": task_id}) == 1
    assert repo.count("blue_proposal", {"task_id": task_id}) == 0


def test_round_inconclusive_when_service_missing(repo):
    task_id = "ctrl-missing"
    reg = ServiceRegistry()  # no services at all
    outcome = RoundController(repo, reg).run_round(_round_request(task_id))
    assert outcome.outcome == "inconclusive"
    assert "no service wired" in outcome.reason
    # round_request + feedback still persisted
    assert repo.count("round_request", {"task_id": task_id}) == 1
    assert repo.count("feedback_record", {"task_id": task_id}) == 1


def test_invalid_contract_output_from_service_is_rejected(repo):
    # A service claiming red_proposal but returning junk must be rejected by the store.
    task_id = "ctrl-bad-output"
    reg = ServiceRegistry()
    reg.register("red", static_service("red_proposal", lambda _p: {"task_id": task_id}))
    steps = [RoundStep("red", lambda ctx: {"task_id": ctx["task_id"]})]
    import pytest
    from shared_services.datastore.repository import ContractViolation
    with pytest.raises(ContractViolation):
        RoundController(repo, reg, steps=steps).run_round(_round_request(task_id))
