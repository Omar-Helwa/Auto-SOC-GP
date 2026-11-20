"""Epic B tests — local models, validation, and serialization.

Covers:
- the shared example files validate (valid) / fail (invalid) as expected;
- Python constants do not drift from the schema enums;
- models round-trip through the contract shape and stay valid;
- the serializer refuses to emit an invalid proposal;
- the error builder produces contract-valid error_response payloads.
"""

from __future__ import annotations

import pytest

from schemas import constants, errors, models, serializer, validation
from schemas._loader import schema_enum


# --------------------------------------------------------------------------- #
# Contract examples validate as advertised
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "contract, validator",
    [
        ("red_proposal", validation.validate_red_proposal),
        ("red_input", validation.validate_red_input),
        ("error_response", validation.validate_error_response),
        ("evidence_reference", validation.validate_evidence_reference),
    ],
)
def test_valid_example_passes(example, contract, validator):
    result = validator(example(contract, "valid"))
    assert result.ok, result.summary()


@pytest.mark.parametrize(
    "contract, validator",
    [
        ("red_proposal", validation.validate_red_proposal),
        ("red_input", validation.validate_red_input),
        ("error_response", validation.validate_error_response),
        ("evidence_reference", validation.validate_evidence_reference),
    ],
)
def test_invalid_example_fails(example, contract, validator):
    result = validator(example(contract, "invalid"))
    assert not result.ok
    assert result.errors  # at least one concrete reason


# --------------------------------------------------------------------------- #
# Constants stay in sync with the schema (no drift)
# --------------------------------------------------------------------------- #
def test_constants_match_schema():
    assert list(constants.SCENARIO_FAMILIES) == schema_enum(
        "red_proposal", ("properties", "scenario", "properties", "family")
    )
    assert list(constants.WORKFLOW_ACTIONS) == schema_enum(
        "red_proposal", ("$defs", "workflow_step", "properties", "action")
    )
    assert list(constants.EVIDENCE_TYPES) == schema_enum(
        "evidence_reference", ("properties", "evidence_type")
    )
    assert list(constants.ERROR_CATEGORIES) == schema_enum(
        "error_response", ("properties", "category")
    )


# --------------------------------------------------------------------------- #
# Models round-trip and produce contract-valid output
# --------------------------------------------------------------------------- #
def test_proposal_model_roundtrip_is_valid(example):
    raw = example("red_proposal", "valid")
    proposal = models.RedProposal.from_dict(raw)
    rebuilt = proposal.to_dict()
    assert validation.validate_red_proposal(rebuilt).ok
    # key fields survive the round trip
    assert rebuilt["proposal_id"] == raw["proposal_id"]
    assert len(rebuilt["scenario"]["workflow_steps"]) == len(raw["scenario"]["workflow_steps"])


def test_input_model_roundtrip_is_valid(example):
    raw = example("red_input", "valid")
    red_input = models.RedInput.from_dict(raw)
    rebuilt = red_input.to_dict()
    assert validation.validate_red_input(rebuilt).ok
    assert rebuilt["task_id"] == raw["task_id"]


def test_built_proposal_from_scratch_is_valid():
    proposal = models.RedProposal(
        proposal_id="p-1",
        task_id="t-1",
        prompt_version="red-system@0.1.0",
        detection_under_test=models.DetectionUnderTest("det-1", "1.0.0"),
        scenario=models.Scenario(
            family="it_maintenance",
            title="Routine patch install",
            description="WSUS installs monthly patches via the update agent.",
            workflow_steps=[
                models.WorkflowStep(
                    action="process_execution",
                    target="wuauclt.exe",
                    benign_context="Scheduled Windows Update agent run.",
                )
            ],
        ),
        benign_justification="Monthly patching is routine IT maintenance.",
    )
    payload = serializer.proposal_to_contract(proposal)
    assert validation.validate_red_proposal(payload).ok
    # constraints_ack is always emitted and all-true
    assert payload["constraints_ack"] == {
        "within_allowed_families": True,
        "no_execution": True,
        "no_verdict": True,
    }


# --------------------------------------------------------------------------- #
# Serializer refuses invalid output
# --------------------------------------------------------------------------- #
def test_serializer_rejects_out_of_enum_family():
    bad = models.RedProposal(
        proposal_id="p-2",
        task_id="t-2",
        prompt_version="v",
        detection_under_test=models.DetectionUnderTest("det", "1.0.0"),
        scenario=models.Scenario(
            family="arbitrary_red_team_ops",  # not in enum
            title="x",
            description="y",
            workflow_steps=[models.WorkflowStep("process_execution", "z", "ctx")],
        ),
        benign_justification="j",
    )
    with pytest.raises(serializer.RedContractError):
        serializer.proposal_to_contract(bad)


def test_serializer_rejects_zero_steps():
    bad = models.RedProposal(
        proposal_id="p-3",
        task_id="t-3",
        prompt_version="v",
        detection_under_test=models.DetectionUnderTest("det", "1.0.0"),
        scenario=models.Scenario(
            family="admin_automation",
            title="x",
            description="y",
            workflow_steps=[],  # violates minItems: 1
        ),
        benign_justification="j",
    )
    with pytest.raises(serializer.RedContractError):
        serializer.proposal_to_contract(bad)


# --------------------------------------------------------------------------- #
# Error building
# --------------------------------------------------------------------------- #
def test_build_error_response_is_contract_valid():
    err = errors.build_error_response(
        "missing_information",
        "Red input is missing detection.logic_summary.",
        task_id="t-1",
        details={"missing_fields": ["detection.logic_summary"]},
    )
    assert validation.validate_error_response(err).ok
    assert err["retryable"] is False  # default for missing_information
    assert err["source_component"] == "02_red_role"


def test_build_error_response_rejects_unknown_category():
    with pytest.raises(ValueError):
        errors.build_error_response("malformed", "nope")


def test_input_error_category_classification(example):
    # The invalid red_input example is missing a required field.
    result = validation.validate_red_input(example("red_input", "invalid"))
    assert not result.ok
    assert validation.input_error_category(result) == "missing_information"
