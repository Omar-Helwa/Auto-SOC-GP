"""Deterministic rule editing (apply_edits)."""

from __future__ import annotations

import pytest
import yaml

from rule_edits import EditError, apply_edits
from schemas.models import BlueInput, BlueProposal, FieldCondition, RuleEdit


@pytest.fixture
def inp(example) -> BlueInput:
    return BlueInput.from_dict(example("blue_input", "valid"))


@pytest.fixture
def prop(example) -> BlueProposal:
    return BlueProposal.from_dict(example("blue_proposal", "valid"))


# --------------------------------------------------------------------------- #
# apply_edits
# --------------------------------------------------------------------------- #
def test_add_exclusion_rewrites_condition(inp, prop):
    cand = apply_edits(inp.detection.rule_text, prop.edits)
    det = cand.rule["detection"]
    assert cand.filters_added == ["filter_autosoc_1"]
    assert det["condition"] == "(selection_img and selection_cli) and not filter_autosoc_1"
    assert det["filter_autosoc_1"]["User"] == "CORP\\svc_inventory"
    assert det["filter_autosoc_1"]["ParentImage|endswith"] == "\\svchost.exe"
    assert list(det)[-1] == "condition"
    assert "+  filter_autosoc_1:" in cand.diff
    assert yaml.safe_load(cand.rule_text) == cand.rule  # output re-parses identically


def test_two_exclusions_get_distinct_names(inp, prop):
    cand = apply_edits(inp.detection.rule_text, prop.edits + prop.edits)
    assert cand.filters_added == ["filter_autosoc_1", "filter_autosoc_2"]


def test_narrow_selection(inp):
    edit = RuleEdit("narrow_selection", [FieldCondition("IntegrityLevel", "equals", ["High"])], "r", "selection_img")
    cand = apply_edits(inp.detection.rule_text, [edit])
    assert cand.rule["detection"]["selection_img"]["IntegrityLevel"] == "High"
    assert cand.selections_narrowed == ["selection_img"]


@pytest.mark.parametrize("target,needle", [("nope", "does not exist"), ("condition", "does not exist")])
def test_narrow_selection_bad_target(inp, target, needle):
    edit = RuleEdit("narrow_selection", [FieldCondition("User", "equals", ["CORP\\x"])], "r", target)
    with pytest.raises(EditError, match=needle):
        apply_edits(inp.detection.rule_text, [edit])


def test_narrow_selection_refuses_filters_and_overwrites(inp, prop):
    cand = apply_edits(inp.detection.rule_text, prop.edits)
    widen = RuleEdit("narrow_selection", [FieldCondition("Image", "equals", ["abc"])], "r", "filter_autosoc_1")
    with pytest.raises(EditError, match="widens"):
        apply_edits(cand.rule_text, [widen])
    overwrite = RuleEdit("narrow_selection", [FieldCondition("Image", "endswith", ["\\x.exe"])], "r", "selection_img")
    with pytest.raises(EditError, match="already has"):
        apply_edits(inp.detection.rule_text, [overwrite])
