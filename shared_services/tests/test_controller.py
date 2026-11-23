"""Controller tests — relaying, persistence, and error handling."""

from __future__ import annotations

import json
from pathlib import Path

from shared_services.controller.round_controller import RoundController, RoundStep
from shared_services.controller.services import ServiceRegistry, static_service

REPO_ROOT = Path(__file__).resolve().parents[2]


def _round_request(task_id="ctrl-t-1"):
    path = REPO_ROOT / "00_shared_contracts" / "round_request" / "examples" / "valid_round_request.json"
    request = json.loads(path.read_text(encoding="utf-8"))
    request["task_id"] = task_id
    return request


def _example(folder, name, task_id=None):
    path = REPO_ROOT / "00_shared_contracts" / folder / "examples" / name
    data = json.loads(path.read_text(encoding="utf-8"))
    data = {k: v for k, v in data.items() if not k.startswith("_")}
    if task_id is not None:
        data["task_id"] = task_id
    return data


def _full_registry(task_id, red_proposal_example):
    red_proposal_example = dict(red_proposal_example)
    red_proposal_example["task_id"] = task_id
    reg = ServiceRegistry()
    reg.register("red", static_service("red_proposal", lambda _p: red_proposal_example))
    telemetry = {
        "contract_version": "0.1.0",
        "evidence_id": f"evidence-{task_id}",
        "task_id": task_id,
        "detection_id": "det-susp-powershell",
        "evidence_type": "telemetry",
        "evidence_ref": f"evidence://{task_id}/telemetry",
        "verified": True,
    }
    reg.register("platform_execute", static_service("telemetry_evidence", lambda _p: telemetry))
    labels = _example("telemetry_evidence", "valid_reviewed_label_set.json")
    reg.register("platform_labels", static_service("reviewed_label_set", lambda _p: labels))
    baseline = _example("candidate_rule", "valid_match_set.json", task_id)
    baseline["role"] = "baseline"
    baseline.pop("candidate_ref", None)
    baseline["rule_version"] = "1.0.0"
    reg.register("platform_baseline", static_service("match_set", lambda _p: baseline))

    blue = _example("blue_proposal", "valid_blue_proposal.json", task_id)
    candidate_match_set = _example("candidate_rule", "valid_match_set.json", task_id)
    candidate = _example("candidate_rule", "valid_candidate_rule.json", task_id)
    candidate_match_set["candidate_ref"] = candidate["candidate_id"]
    candidate_match_set["rule_version"] = candidate["candidate_rule_version"]
    reg.register("blue", static_service("blue_proposal", lambda _p: blue))
    reg.register("platform_compile", static_service("candidate_rule", lambda _p: candidate))
    reg.register(
        "platform_candidate_matches",
        static_service("match_set", lambda _p: candidate_match_set),
    )
    judge_result = _example("judge_result", "valid_judge_result_pass.json", task_id)
    reg.register("judge", static_service("judge_result", lambda _p: judge_result))
    return reg


def test_full_round_completes_and_persists(repo, red_proposal_example):
    task_id = "ctrl-complete"
    reg = _full_registry(task_id, red_proposal_example)
    outcome = RoundController(repo, reg).run_round(_round_request(task_id))

    assert outcome.outcome == "completed"
    assert outcome.feedback_id
    # every expected collection has the round's document
    for contract in ("round_request", "red_proposal", "telemetry_evidence",
                     "blue_proposal", "candidate_rule",
                     "judge_result", "feedback_record"):
        assert repo.count(contract, {"task_id": task_id}) == 1
    assert repo.count("reviewed_label_set", {"label_set_id": "ls-0001"}) == 1
    assert repo.count("match_set", {"task_id": task_id}) == 2


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
    # The request persists, but a feedback_record requires a Judge result.
    assert repo.count("round_request", {"task_id": task_id}) == 1
    assert outcome.feedback_id == ""
    assert repo.count("feedback_record", {"task_id": task_id}) == 0


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


def test_red_input_is_built_from_the_contract_round_request():
    from shared_services.controller.round_controller import _red_input_from_context

    request = _round_request("ctrl-red-input")
    red_input = _red_input_from_context({"task_id": "ctrl-red-input", "round_request": request})
    assert red_input["prompt_version"] == request["versions"]["red_prompt"]
    assert "rule_text" not in red_input["detection"]  # red never gets the executable rule
    assert red_input["permitted_evidence_refs"] == request["permitted_evidence_refs"]
