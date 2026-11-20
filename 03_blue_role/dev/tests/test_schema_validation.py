"""Contracts, models and serializer for the Blue component."""

from __future__ import annotations

import pytest

from schemas import constants, errors, serializer, validation
from schemas._loader import load_schema, schema_enum, schema_node
from schemas.models import BlueInput, BlueProposal


# --------------------------------------------------------------------------- #
# Schemas are valid JSON Schema and examples behave
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["blue_proposal", "blue_input", "error_response", "evidence_reference"])
def test_schema_files_are_valid_json_schema(name):
    from jsonschema import Draft202012Validator

    Draft202012Validator.check_schema(load_schema(name))


def test_valid_examples_pass(example):
    assert validation.validate_blue_input(example("blue_input", "valid"))
    assert validation.validate_blue_proposal(example("blue_proposal", "valid"))


def test_invalid_input_example_fails_for_the_documented_reasons(example):
    result = validation.validate_blue_input(example("blue_input", "invalid"))
    assert not result.ok
    paths = {e.path for e in result.errors}
    assert {"must_detect", "detection/rule_format", "edit_constraints/max_edits"} <= paths


def test_invalid_proposal_example_fails_for_the_documented_reasons(example):
    result = validation.validate_blue_proposal(example("blue_proposal", "invalid"))
    assert not result.ok
    keywords = {e.keyword for e in result.errors}
    assert {"pattern", "enum", "additionalProperties"} <= keywords
    assert any(e.path.startswith("edits/2") for e in result.errors)  # narrow without target


# --------------------------------------------------------------------------- #
# Targeted rules of the blue_proposal contract
# --------------------------------------------------------------------------- #
def test_wildcards_are_rejected(example):
    p = example("blue_proposal", "valid")
    p["edits"][0]["conditions"][0]["values"] = ["CORP\\svc_*"]
    assert not validation.validate_blue_proposal(p)


def test_edit_budget_is_bounded(example):
    p = example("blue_proposal", "valid")
    p["edits"] = p["edits"] * 6
    assert not validation.validate_blue_proposal(p)


def test_add_exclusion_may_not_name_a_target(example):
    p = example("blue_proposal", "valid")
    p["edits"][0]["target_selection"] = "selection_img"
    assert not validation.validate_blue_proposal(p)


def test_narrow_selection_requires_a_target(example):
    p = example("blue_proposal", "valid")
    p["edits"][0]["operation"] = "narrow_selection"
    assert not validation.validate_blue_proposal(p)
    p["edits"][0]["target_selection"] = "selection_img"
    assert validation.validate_blue_proposal(p)


def test_constraints_ack_cannot_be_false(example):
    p = example("blue_proposal", "valid")
    p["constraints_ack"]["no_judge_criteria_change"] = False
    assert not validation.validate_blue_proposal(p)


def test_proposal_cannot_carry_a_verdict(example):
    p = example("blue_proposal", "valid")
    p["decision"] = "accepted"
    assert not validation.validate_blue_proposal(p)


# --------------------------------------------------------------------------- #
# Drift: Python constants == schema enums
# --------------------------------------------------------------------------- #
def test_constants_match_schema():
    assert tuple(schema_enum("blue_proposal", ("$defs", "rule_edit", "properties", "operation"))) == constants.EDIT_OPERATIONS
    assert tuple(schema_enum("blue_proposal", ("$defs", "field_condition", "properties", "modifier"))) == constants.CONDITION_MODIFIERS
    assert tuple(schema_enum("blue_input", ("properties", "detection", "properties", "rule_format"))) == constants.RULE_FORMATS
    assert tuple(schema_enum("error_response", ("properties", "category"))) == constants.ERROR_CATEGORIES
    assert tuple(schema_enum("evidence_reference", ("properties", "evidence_type"))) == constants.EVIDENCE_TYPES
    edits = schema_node("blue_proposal", ("properties", "edits"))
    assert (edits["minItems"], edits["maxItems"]) == (constants.MIN_EDITS, constants.MAX_EDITS)


def test_blue_evidence_reference_matches_shared_contract():
    shared = load_schema("evidence_reference")
    local = schema_node("blue_proposal", ("$defs", "evidence_reference"))
    assert local["required"] == shared["required"]
    assert local["properties"]["evidence_type"]["enum"] == shared["properties"]["evidence_type"]["enum"]


# --------------------------------------------------------------------------- #
# Models + serializer
# --------------------------------------------------------------------------- #
def test_input_parses_into_models(example):
    inp = BlueInput.from_dict(example("blue_input", "valid"))
    assert inp.detection.detection_id == "win-encoded-powershell"
    assert inp.false_positives[0].evidence_id == "ev-2026-11-10-fp-inventory-01"
    assert "CommandLine" in inp.edit_constraints.attacker_controllable_fields


def test_proposal_round_trips(example):
    data = example("blue_proposal", "valid")
    assert serializer.proposal_to_contract(BlueProposal.from_dict(data)) == data


def test_serializer_refuses_invalid_output(example):
    prop = BlueProposal.from_dict(example("blue_proposal", "valid"))
    prop.edits = []
    with pytest.raises(errors.BlueContractError):
        serializer.proposal_to_contract(prop)


def test_error_response_is_contract_valid():
    err = errors.build_error_response("dependency", "model gateway down", task_id="t-1")
    assert serializer.error_to_contract(err)["retryable"] is True
    assert err["source_component"] == "03_blue_role"


def test_input_error_category(example):
    bad = example("blue_input", "valid")
    del bad["must_detect"]
    assert validation.input_error_category(validation.validate_blue_input(bad)) == "missing_information"
    bad = example("blue_input", "valid")
    bad["edit_constraints"]["max_edits"] = 0
    assert validation.input_error_category(validation.validate_blue_input(bad)) == "validation"
