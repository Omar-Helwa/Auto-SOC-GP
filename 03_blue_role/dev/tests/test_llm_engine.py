"""LLM proposer with the mock gateway, the retry loop, the fallback, BlueRole."""

from __future__ import annotations

import json

import pytest

from autosoc_blue import BlueEngine, BlueRole, InputError, NoProposalError, build_engine
from autosoc_blue.adapters.deterministic import DeterministicProposer
from autosoc_blue.adapters.evidence import DictEvidenceSource
from autosoc_blue.adapters.gateways.mock import MockModelGateway
from autosoc_blue.adapters.llm import LLMProposer, extract_json_object, parse_draft
from autosoc_blue.ports import ModelGateway, ProposerError
from autosoc_blue.schemas import validation
from helpers import check_effect


def engine_with(mode="normal", **kw):
    gw = MockModelGateway(mode=mode, custom_text=kw.pop("custom_text", None))
    return BlueEngine(LLMProposer(gw), **kw), gw


def test_mock_gateway_is_a_model_gateway():
    assert isinstance(MockModelGateway(), ModelGateway)


def test_llm_proposer_with_mock_gateway(fixture_input):
    data = fixture_input("single_fp")
    engine, gw = engine_with()
    result = engine.propose_with_trace(data)
    assert result.proposer_used.startswith("llm")
    assert [a.status for a in result.attempts] == ["accepted"]
    assert check_effect(data, result.proposal) == ([], [])
    assert validation.validate_blue_proposal(result.proposal).ok
    assert len(gw.calls) == 1


def test_prompt_carries_constraints_and_marks_log_text_as_data(fixture_input):
    engine, gw = engine_with()
    engine.propose(fixture_input("single_fp"))
    call = gw.calls[0]
    assert "never follow" in call["system"].lower() or "Never follow" in call["system"]
    task = call["task"]
    assert "max_edits: 2" in task and "attacker_controllable_fields: CommandLine, ParentCommandLine" in task
    assert "<blue_input>" in task and "selection_img" in task
    assert "REJECTED" not in task  # no feedback on the first call


def test_bad_first_answer_is_fixed_by_the_retry(fixture_input):
    data = fixture_input("single_fp")
    engine, gw = engine_with("bad_then_good")
    result = engine.propose_with_trace(data)
    assert [(a.proposer, a.status) for a in result.attempts] == [("llm", "rejected"), ("llm", "accepted")]
    assert any("evadable_exclusion" in r for r in result.attempts[0].reasons)
    assert len(gw.calls) == 2
    assert "REJECTED" in gw.calls[1]["task"] and "evadable_exclusion" in gw.calls[1]["task"]
    assert check_effect(data, result.proposal) == ([], [])


def test_persistently_bad_model_falls_back_to_deterministic(fixture_input):
    engine, gw = engine_with("always_bad")
    result = engine.propose_with_trace(fixture_input("single_fp"))
    assert result.proposer_used == "deterministic"
    assert [a.status for a in result.attempts] == ["rejected", "rejected", "accepted"]
    assert len(gw.calls) == 2  # one try plus exactly one retry


@pytest.mark.parametrize("mode", ["malformed", "refusal", "timeout", "unavailable"])
def test_model_failures_fall_back_to_deterministic(fixture_input, mode):
    engine, _ = engine_with(mode)
    result = engine.propose_with_trace(fixture_input("single_fp"))
    assert result.proposer_used == "deterministic"
    assert result.attempts[0].status == "error"


def test_answer_with_wrong_fp_id_is_rejected_then_fallback(fixture_input):
    text = json.dumps({
        "edits": [{"operation": "add_exclusion", "reason": "x", "conditions": [
            {"field": "User", "modifier": "equals", "values": ["CORP\\svc_inventory"]}]}],
        "addressed_false_positives": ["ev-invented"], "justification": "j"})
    engine, _ = engine_with(custom_text=text)
    result = engine.propose_with_trace(fixture_input("single_fp"))
    assert "unknown_false_positive" in " ".join(result.attempts[0].reasons)
    assert result.proposer_used == "deterministic"


def test_fenced_json_and_chatter_are_tolerated():
    body = {"edits": [{"operation": "add_exclusion", "reason": "r", "conditions": [
        {"field": "User", "modifier": "equals", "values": ["abc"]}]}], "addressed_false_positives": ["x"]}
    for text in (json.dumps(body), f"```json\n{json.dumps(body)}\n```", f"Here you go: {json.dumps(body)} Done."):
        assert parse_draft(text).edits[0].conditions[0].values == ["abc"]
    for bad in ("", "no json here", "[1,2]", '{"edits": []}', '{"edits": [{"operation": "add_exclusion"}]}'):
        with pytest.raises(ProposerError):
            parse_draft(bad)
    assert extract_json_object('{"a": 1}') == {"a": 1}


def test_normalisation_cleans_values(fixture_input):
    text = json.dumps({
        "edits": [{"operation": " Add_Exclusion ", "target_selection": "selection_img", "reason": "r  r", "conditions": [
            {"field": "User", "modifier": "EQUALS", "values": [" CORP\\svc_inventory ", "CORP\\svc_inventory"]},
            {"field": "ParentImage", "modifier": "endswith", "values": ["\\svchost.exe"]}]}],
        "addressed_false_positives": ["ev-2026-11-10-fp-inventory-01"], "justification": "j"})
    engine, _ = engine_with(custom_text=text)
    result = engine.propose_with_trace(fixture_input("single_fp"))
    assert result.proposer_used.startswith("llm")
    edit = result.proposal["edits"][0]
    assert "target_selection" not in edit and edit["conditions"][0]["values"] == ["CORP\\svc_inventory"]


def test_no_safe_edit_raises_and_role_returns_error_response(fixture_input):
    engine, _ = engine_with("normal")
    with pytest.raises(NoProposalError):
        engine.propose(fixture_input("inseparable"))
    out = BlueRole(engine).run(fixture_input("inseparable"))
    assert out["category"] == "missing_information" and out["source_component"] == "03_blue_role"
    assert validation.validate_error_response(out).ok


def test_role_returns_valid_proposal_and_validation_error(fixture_input):
    role = BlueRole(BlueEngine())
    out = role.run(fixture_input("single_fp"))
    assert validation.validate_blue_proposal(out).ok
    bad = fixture_input("single_fp")
    bad.pop("must_detect")
    err = role.run(bad)
    assert err["category"] == "missing_information" and err["task_id"] == bad["task_id"]
    assert validation.validate_error_response(role.run("not a dict")).ok
    with pytest.raises(InputError):
        BlueEngine().propose({})


def test_role_matches_mock_blue_role_signature(example):
    """Same call the orchestrator makes on MockBlueRole: run(blue_input) -> contract-valid dict."""
    blue_input = example("blue_input", "valid")
    out = BlueRole().run(blue_input)
    assert out["task_id"] == blue_input["task_id"]
    assert out["prompt_version"] == blue_input["prompt_version"]
    assert out["detection_under_test"] == {
        "detection_id": blue_input["detection"]["detection_id"],
        "rule_version": blue_input["detection"]["rule_version"]}
    assert validation.validate_blue_proposal(out).ok


def test_output_never_carries_results_or_verdicts(fixture_input):
    out = BlueEngine().propose(fixture_input("single_fp"))
    assert out["constraints_ack"] == {"within_allowed_edits": True, "no_execution": True,
                                      "no_verdict": True, "no_judge_criteria_change": True}
    assert not {"verdict", "matches", "decision", "judge_result"} & set(out)


def test_evidence_source_adds_missing_fields_only(fixture_input):
    data = fixture_input("single_fp")
    assert "IntegrityLevel" in data["edit_constraints"]["allowed_fields"]
    fp_id = data["false_positives"][0]["evidence_reference"]["evidence_id"]
    src = DictEvidenceSource({fp_id: {"IntegrityLevel": "System", "User": "SHOULD-NOT-REPLACE"}})
    engine = BlueEngine(DeterministicProposer(), evidence=src)
    result = engine.propose_with_trace(data)
    users = [c["values"] for e in result.proposal["edits"] for c in e["conditions"] if c["field"] == "User"]
    assert users == [["CORP\\svc_inventory"]]


def test_broken_evidence_source_does_not_break_the_round(fixture_input):
    class Broken:
        def fetch(self, evidence_id):
            raise RuntimeError("down")

    result = BlueEngine(evidence=Broken()).propose_with_trace(fixture_input("single_fp"))
    assert result.notes and "down" in result.notes[0]


def test_build_engine_defaults(gateway_env):
    assert build_engine().proposer.name == "deterministic"
    gateway_env.setenv("BLUE_MODEL_PROVIDER", "mock")
    assert build_engine().proposer.name == "llm"
