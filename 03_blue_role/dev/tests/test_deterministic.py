"""The deterministic baseline proposer, end to end through the engine, on the fixtures."""

from __future__ import annotations

import pytest

from autosoc_blue import BlueEngine, NoProposalError
from autosoc_blue.adapters.deterministic import DeterministicProposer
from autosoc_blue.ports import ProposerError
from autosoc_blue.schemas import validation
from helpers import check_effect, context_for


@pytest.mark.parametrize("name", ["single_fp", "multi_fp", "narrow_only", "needs_commandline"])
def test_proposal_is_valid_removes_fps_and_keeps_attacks(fixture_input, name):
    data = fixture_input(name)
    proposal = BlueEngine(DeterministicProposer()).propose(data)
    assert validation.validate_blue_proposal(proposal).ok
    still_fp, lost = check_effect(data, proposal)
    assert still_fp == [] and lost == []
    assert proposal["task_id"] == data["task_id"]
    assert proposal["prompt_version"] == data["prompt_version"]
    assert proposal["detection_under_test"] == {
        "detection_id": data["detection"]["detection_id"], "rule_version": data["detection"]["rule_version"]}
    assert len(proposal["edits"]) <= data["edit_constraints"]["max_edits"]


def test_single_fp_uses_identity_and_lineage_not_commandline(fixture_input):
    proposal = BlueEngine(DeterministicProposer()).propose(fixture_input("single_fp"))
    (edit,) = proposal["edits"]
    assert edit["operation"] == "add_exclusion"
    fields = {c["field"] for c in edit["conditions"]}
    assert fields == {"User", "ParentImage"}
    assert all(c["modifier"] == "equals" for c in edit["conditions"])


def test_two_service_accounts_become_one_merged_exclusion(fixture_input):
    proposal = BlueEngine(DeterministicProposer()).propose(fixture_input("multi_fp"))
    (edit,) = proposal["edits"]
    user = next(c for c in edit["conditions"] if c["field"] == "User")
    assert sorted(user["values"]) == ["CORP\\svc_inventory", "CORP\\svc_inventory2"]
    assert len(proposal["addressed_false_positives"]) == 2


def test_narrow_only_uses_narrow_selection_on_converging_field(fixture_input):
    proposal = BlueEngine(DeterministicProposer()).propose(fixture_input("narrow_only"))
    (edit,) = proposal["edits"]
    assert edit["operation"] == "narrow_selection"
    assert edit["target_selection"] == "selection_img"
    assert edit["conditions"] == [{"field": "IntegrityLevel", "modifier": "equals", "values": ["High"]}]


def test_attacker_field_is_only_an_extra_condition(fixture_input):
    proposal = BlueEngine(DeterministicProposer()).propose(fixture_input("needs_commandline"))
    (edit,) = proposal["edits"]
    fields = [c["field"] for c in edit["conditions"]]
    assert "CommandLine" in fields and set(fields) - {"CommandLine"}  # never alone


def test_values_never_come_from_a_field_not_allowed(fixture_input):
    data = fixture_input("single_fp")
    data["edit_constraints"]["allowed_fields"] = ["Image", "ParentImage"]
    proposal = BlueEngine(DeterministicProposer()).propose(data)
    for edit in proposal["edits"]:
        assert {c["field"] for c in edit["conditions"]} <= {"Image", "ParentImage"}


def test_inseparable_evidence_gives_no_proposal(fixture_input):
    proposer = DeterministicProposer()
    with pytest.raises(ProposerError, match="no safe edit"):
        proposer.propose(context_for(fixture_input("inseparable")))
    with pytest.raises(NoProposalError) as exc:
        BlueEngine(proposer).propose(fixture_input("inseparable"))
    assert exc.value.category == "missing_information"


def test_budget_of_one_edit_with_unrelated_false_positives(fixture_input):
    data = fixture_input("multi_fp")
    fp2 = data["false_positives"][1]["observed_fields"]
    fp2["User"] = "CORP\\other_admin"
    fp2["ParentImage"] = "C:\\Windows\\System32\\taskhostw.exe"
    # An attack that mixes the two identities: merging both exclusions would hide it.
    data["must_detect"][1]["observed_fields"].update(
        {"User": "CORP\\other_admin", "ParentImage": "C:\\Windows\\System32\\svchost.exe"})
    data["edit_constraints"]["max_edits"] = 1
    assert len(BlueEngine(DeterministicProposer()).propose({**data, "edit_constraints": {
        **data["edit_constraints"], "max_edits": 2}})["edits"]) == 2
    engine = BlueEngine(DeterministicProposer())
    with pytest.raises(NoProposalError):  # strict: a single edit cannot cover both
        engine.propose(data)
    partial = BlueEngine(DeterministicProposer(), allow_partial=True).propose(data)
    assert len(partial["edits"]) == 1
    assert len(partial["addressed_false_positives"]) == 1
    assert "Partial" in partial["rationale"]


def test_merge_when_the_cross_product_is_safe(fixture_input):
    data = fixture_input("multi_fp")
    data["false_positives"][1]["observed_fields"]["ParentImage"] = "C:\\Windows\\System32\\taskhostw.exe"
    proposal = BlueEngine(DeterministicProposer()).propose(data)
    assert len(proposal["edits"]) == 1 and check_effect(data, proposal) == ([], [])


def test_same_input_same_edits(fixture_input):
    a = BlueEngine(DeterministicProposer()).propose(fixture_input("multi_fp"))
    b = BlueEngine(DeterministicProposer()).propose(fixture_input("multi_fp"))
    assert a["edits"] == b["edits"]
    assert a["proposal_id"] != b["proposal_id"]
