"""End-to-end tests for the Red component (Epic G5).

Exercises every path through RedRole.run using the mock model gateway: normal,
missing-info, malformed, refusal, timeout, dependency, out-of-scope, and
determinism. No live model, orchestrator, blue, judge, or Splunk involved.
"""

from __future__ import annotations

import json

from interfaces.red_role import RedRole
from schemas import validation

from mock_gateway import MockModelGateway  # flat module (see conftest path setup)
from mock_telemetry import sample_refs


def _run(fixture_dict, mode="normal", custom_text=None):
    gw = MockModelGateway(mode=mode, custom_text=custom_text)
    return RedRole(gw).run(fixture_dict), gw


def test_normal_round_returns_valid_proposal(fixture):
    out, gw = _run(fixture("valid_task.json"))
    assert validation.validate_red_proposal(out).ok, out
    assert out["task_id"] == "fixture-round-0001"
    # controlled fields are stamped by the component, not the model
    assert out["detection_under_test"]["detection_id"] == "win-encoded-powershell"
    assert out["prompt_version"] == "red-system@0.1.0"
    assert out["constraints_ack"] == {
        "within_allowed_families": True, "no_execution": True, "no_verdict": True
    }
    # the gateway was actually called with a rendered prompt
    assert gw.calls and "Detection under test" in gw.calls[0]["task"]


def test_missing_info_returns_missing_information_error(fixture):
    out, _ = _run(fixture("missing_info_task.json"))
    assert validation.validate_error_response(out).ok
    assert out["category"] == "missing_information"
    assert out["retryable"] is False
    assert out["source_component"] == "02_red_role"


def test_malformed_model_output_returns_validation_error(fixture):
    out, _ = _run(fixture("valid_task.json"), mode="malformed")
    assert validation.validate_error_response(out).ok
    assert out["category"] == "validation"


def test_malformed_model_evidence_reference_returns_validation_error(fixture, example):
    proposal = example("red_proposal", "valid")
    model_output = {
        "scenario": proposal["scenario"],
        "benign_justification": proposal["benign_justification"],
        "evidence_references": ["invented-reference"],
    }
    out, _ = _run(
        fixture("valid_task.json"),
        custom_text=json.dumps(model_output),
    )
    assert validation.validate_error_response(out).ok
    assert out["category"] == "validation"
    assert "malformed evidence reference" in out["message"]


def test_refusal_returns_validation_error(fixture):
    out, _ = _run(fixture("valid_task.json"), mode="refusal")
    assert validation.validate_error_response(out).ok
    assert out["category"] == "validation"


def test_timeout_returns_timeout_error(fixture):
    out, _ = _run(fixture("valid_task.json"), mode="timeout")
    assert validation.validate_error_response(out).ok
    assert out["category"] == "timeout"
    assert out["retryable"] is True


def test_unavailable_returns_dependency_error(fixture):
    out, _ = _run(fixture("valid_task.json"), mode="unavailable")
    assert validation.validate_error_response(out).ok
    assert out["category"] == "dependency"
    assert out["retryable"] is True


def test_out_of_scope_family_is_rejected(fixture):
    # valid_task allows admin_automation/it_maintenance/developer_activity, NOT security_tooling
    out, _ = _run(fixture("valid_task.json"), mode="out_of_scope")
    assert validation.validate_error_response(out).ok
    assert out["category"] == "validation"
    assert "out of scope" in out["message"]


def test_determinism_same_input_same_proposal_scenario(fixture):
    out1, _ = _run(fixture("valid_task.json"))
    out2, _ = _run(fixture("valid_task.json"))
    # proposal_id differs (random), but the scenario content is identical
    assert out1["scenario"] == out2["scenario"]
    assert out1["benign_justification"] == out2["benign_justification"]


def test_evidence_refs_flow_through(fixture):
    task = fixture("valid_task.json")
    task["permitted_evidence_refs"] = sample_refs(1)
    out, gw = _run(task)
    assert validation.validate_red_proposal(out).ok
    # the permitted evidence id appears in the rendered prompt context
    assert "ev-2026-11-10-encoded-ps-baseline" in gw.calls[0]["task"]
