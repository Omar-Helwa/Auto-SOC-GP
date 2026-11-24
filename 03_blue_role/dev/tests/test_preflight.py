"""Pre-flight checks: every rejection reason, the local matcher, unverifiable rules."""

from __future__ import annotations

import pytest

from autosoc_blue.adapters.validators import LocalSigmaValidator
from autosoc_blue.core.draft import Draft
from autosoc_blue.core.preflight import run_preflight
from autosoc_blue.rule_edits import UnsupportedSigma, rule_matches
from autosoc_blue.schemas.models import FieldCondition, RuleEdit
from helpers import context_for

FP = "ev-2026-11-10-fp-inventory-01"


def excl(*conds, op="add_exclusion", target=None):
    return RuleEdit(op, [FieldCondition(*c) for c in conds], "r", target)


def draft(*edits, addressed=(FP,)):
    return Draft(list(edits), list(addressed), "j")


@pytest.fixture
def ctx(fixture_input):
    return context_for(fixture_input("single_fp"))


def preflight(ctx, d, **kw):
    return run_preflight(ctx, d, LocalSigmaValidator(), **kw)


GOOD = ("User", "equals", ["CORP\\svc_inventory"]), ("ParentImage", "endswith", ["\\svchost.exe"])


def test_good_draft_passes(ctx):
    report = preflight(ctx, draft(excl(*GOOD)))
    assert report.ok, report.summary()
    assert report.preview_verified
    assert report.removed_false_positives == [FP]
    assert len(report.kept_must_detect) == 2


def test_commandline_only_exclusion_is_evadable(ctx):
    report = preflight(ctx, draft(excl(("CommandLine", "contains", ["RwBlAHQALQBDAGkA"]))))
    assert "evadable_exclusion" in report.codes()
    assert not report.ok


def test_exclusion_that_hides_an_attack_is_blocked(ctx):
    report = preflight(ctx, draft(excl(("Image", "endswith", ["\\powershell.exe"]))))
    assert "would_lose_attack" in report.codes()
    assert "ev-atomic-t1059.001-office" in report.summary()


def test_edit_that_misses_the_fp_is_flagged(ctx):
    report = preflight(ctx, draft(excl(("User", "equals", ["CORP\\nobody"]))))
    assert "false_positive_not_removed" in report.codes()


def test_too_many_edits_field_and_operation_policy(ctx):
    bad = excl(("Hashes", "equals", ["abc123"]))
    report = preflight(ctx, draft(bad, bad, bad, addressed=("ev-made-up",)))
    assert {"too_many_edits", "field_not_allowed", "unknown_false_positive"} <= set(report.codes())

    ctx.constraints.allowed_operations = ["add_exclusion"]
    narrow = excl(("IntegrityLevel", "equals", ["High"]), op="narrow_selection", target="selection_img")
    assert "operation_not_allowed" in preflight(ctx, draft(narrow)).codes()


def test_value_rules(ctx):
    codes = preflight(ctx, draft(excl(("User", "contains", ["CORP\\*"]), ("ParentImage", "equals", ["ab"])))).codes()
    assert "wildcard_value" in codes and "value_length" in codes


def test_target_selection_rules(ctx):
    missing = excl(("IntegrityLevel", "equals", ["High"]), op="narrow_selection")
    unknown = excl(("IntegrityLevel", "equals", ["High"]), op="narrow_selection", target="nope")
    forbidden = excl(*GOOD, target="selection_img")
    assert "target_selection_missing" in preflight(ctx, draft(missing)).codes()
    assert "target_selection_unknown" in preflight(ctx, draft(unknown)).codes()
    assert "target_selection_forbidden" in preflight(ctx, draft(forbidden)).codes()


def test_unaddressed_false_positive_is_blocking_unless_partial(fixture_input):
    ctx = context_for(fixture_input("multi_fp"))
    d = draft(excl(*GOOD), addressed=(FP,))
    assert "false_positive_not_addressed" in preflight(ctx, d).codes()
    assert "false_positive_not_addressed" not in preflight(ctx, d, allow_partial=True).codes()


def test_empty_draft_and_empty_addressed(ctx):
    assert preflight(ctx, Draft([], [], "")).codes() == ["no_edits"]
    assert "no_false_positive_addressed" in preflight(ctx, draft(excl(*GOOD), addressed=())).codes()


def test_edit_that_cannot_be_applied(ctx):
    dup = excl(("User", "equals", ["CORP\\a"]), ("User", "equals", ["CORP\\b"]))
    assert "edit_not_applicable" in preflight(ctx, draft(dup)).codes()


def test_unsupported_rule_is_unverifiable_not_passed(fixture_input):
    data = fixture_input("single_fp")
    data["detection"]["rule_text"] = data["detection"]["rule_text"].replace("CommandLine|contains:", "CommandLine|re:")
    report = preflight(context_for(data), draft(excl(*GOOD)))
    assert "preview_unverifiable" in report.codes()
    assert report.ok and not report.preview_verified


def test_local_matcher_basics():
    det = {"sel": {"Image|endswith": ["\\a.exe", "\\b.exe"], "User": "bob"}, "condition": "sel"}
    assert rule_matches(det, {"Image": "C:\\x\\A.EXE", "User": "BOB"})
    assert not rule_matches(det, {"Image": "C:\\x\\a.exe", "User": "eve"})
    assert not rule_matches(det, {"User": "bob"})  # missing field never matches
    det2 = {"s1": {"A": "1"}, "s2": {"B": "2"}, "condition": "s1 and not s2"}
    assert rule_matches(det2, {"A": "1"}) and not rule_matches(det2, {"A": "1", "B": "2"})
    with pytest.raises(UnsupportedSigma):
        rule_matches({"s": {"A|re": "x"}, "condition": "s"}, {"A": "x"})
