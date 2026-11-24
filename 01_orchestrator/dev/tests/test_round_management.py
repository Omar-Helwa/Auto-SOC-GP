"""Run from the 01_orchestrator folder:  python -m unittest discover -s dev/tests -v"""

import copy
import json
import os
import sys
import tempfile
import threading
import unittest
import uuid
from functools import lru_cache
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from round_management import (  
    ALLOWED_ARTIFACTS,
    ConcurrencyError,
    DuplicateRoundError,
    InMemoryRoundStore,
    IntegrityError,
    InvalidArgumentError,
    InvalidRoundRequestError,
    InvalidTransitionError,
    JsonFileRoundStore,
    MissingArtifactError,
    MongoRoundStore,
    REQUIRED_ARTIFACTS,
    RetryExhaustedError,
    RoundClosedError,
    RoundConfig,
    RoundManagementError,
    RoundManager,
    RoundNotFoundError,
    RoundState,
    RoundTimedOutError,
    StoreUnavailableError,
    make_error_response,
)
from round_management import contracts

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    HAVE_JSONSCHEMA = True
except ImportError:  # the contract tests below are skipped without jsonschema
    HAVE_JSONSCHEMA = False

REPO_ROOT = Path(__file__).resolve().parents[3]
CONTRACTS_DIR = REPO_ROOT / "00_shared_contracts"

REQUEST = {
    "contract_version": "0.1.0",
    "task_id": "task-001",
    "detection": {
        "detection_id": "win-encoded-powershell",
        "rule_version": "3.2.0",
        "description": "Flags powershell.exe invoked with -EncodedCommand.",
        "logic_summary": "Alerts on powershell.exe with an encoded command argument.",
        "rule_language": "splunk_spl",
        "rule_text": "index=win EventCode=4688 Image=*powershell.exe CommandLine=*-enc*",
    },
    "benign_constraints": {
        "allowed_scenario_families": ["admin_automation", "it_maintenance"],
        "max_workflow_steps": 5,
        "allowed_actions": ["scheduled_task", "script_execution"],
        "forbidden_notes": ["Stay on the lab host only."],
    },
    "dataset": {"dataset_id": "lab-sysmon", "dataset_version": "2026.11.1", "evaluation_set_id": "evalset-01"},
    "criteria": {
        "criteria_id": "criteria-001",
        "criteria_version": "1.0",
        "thresholds": {
            "minimum_attack_retention": 1.0,
            "maximum_new_benign_matches": 0,
        },
    },
    "versions": {
        "red_prompt": "red-system@0.1.0",
        "blue_prompt": "blue-system@0.1.0",
        "model_id": "hosted-model-x",
        "contracts": "0.1.0",
    },
}

# Contract messages a component returns on entering each state.
STATE_ARTIFACTS = {
    RoundState.RED_PROPOSED: {"red_proposal": "audit://task-001/red"},
    RoundState.TELEMETRY_COLLECTED: {},
    RoundState.EVIDENCE_VERIFIED: {"telemetry_evidence": "evidence://task-001/telemetry"},
    RoundState.BLUE_PROPOSED: {"blue_proposal": "audit://task-001/blue"},
    RoundState.CANDIDATE_EXECUTED: {
        "candidate_rule": "evidence://task-001/candidate",
        "candidate_match_set": "evidence://task-001/candidate-matches",
        "baseline_match_set": "evidence://task-001/baseline-matches",
    },
    RoundState.JUDGED: {"judge_result": "audit://task-001/judge"},
}


def request(**overrides):
    out = copy.deepcopy(REQUEST)
    out.update(overrides)
    return out


class FakeClock:
    def __init__(self):
        self.now = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def tick(self, seconds):
        self.now += timedelta(seconds=seconds)


def make_manager(store=None, clock=None):
    counter = iter(range(1, 1000))
    return RoundManager(
        store or InMemoryRoundStore(),
        clock=clock or FakeClock(),
        error_id_factory=lambda: f"err-{next(counter):03d}",
    )


def advance_to(mgr, rid, last):
    for state in (
        RoundState.RED_PROPOSED,
        RoundState.TELEMETRY_COLLECTED,
        RoundState.EVIDENCE_VERIFIED,
        RoundState.BLUE_PROPOSED,
        RoundState.CANDIDATE_EXECUTED,
        RoundState.JUDGED,
    ):
        mgr.advance(rid, state, artifacts=STATE_ARTIFACTS[state])
        if state is last:
            return


def run_to_judged(mgr, rid):
    advance_to(mgr, rid, RoundState.JUDGED)


def unsaved_record():
    """A valid record that no store has seen yet (revision 0)."""
    record = make_manager().create_round(REQUEST)
    record.revision = 0
    return record


def open_round(mgr, **overrides):
    return mgr.create_round(request(**overrides)).round_id


class CreateRoundTests(unittest.TestCase):
    def test_create_freezes_config_and_uses_task_id_as_round_id(self):
        mgr = make_manager()
        req = copy.deepcopy(REQUEST)
        rec = mgr.create_round(req)
        req["detection"]["rule_text"] = "tampered"  # caller mutation must not leak in
        self.assertEqual(rec.state, RoundState.CREATED)
        self.assertEqual(rec.round_id, "task-001")
        self.assertEqual(rec.round_id, rec.config.task_id)
        self.assertIn("-enc", mgr.get_round(rec.round_id).config.detection["rule_text"])
        mgr.verify_integrity(rec.round_id)

    def test_duplicate_task_id_rejected(self):
        mgr = make_manager()
        mgr.create_round(REQUEST)
        with self.assertRaises(DuplicateRoundError):
            mgr.create_round(REQUEST)

    def test_nested_config_values_are_immutable(self):
        config = RoundConfig.from_request(request())
        with self.assertRaises(TypeError):
            config.detection["new"] = "value"
        with self.assertRaises(TypeError):
            config.benign_constraints["max_workflow_steps"] = 9
        with self.assertRaises(AttributeError):
            config.benign_constraints["allowed_actions"].append("registry_operation")
        self.assertEqual(config.to_dict()["benign_constraints"]["allowed_actions"], ["scheduled_task", "script_execution"])
        reused = RoundConfig(
            task_id=config.task_id,
            detection=config.detection,
            benign_constraints=config.benign_constraints,
            dataset=config.dataset,
            criteria=config.criteria,
            versions=config.versions,
        )
        self.assertEqual(reused.fingerprint(), config.fingerprint())

    def test_to_dict_is_a_round_request_that_round_trips(self):
        config = RoundConfig.from_request(request())
        again = RoundConfig.from_request(config.to_dict())
        self.assertEqual(again.fingerprint(), config.fingerprint())
        self.assertEqual(config.to_dict()["limits"], {"max_attempts_per_step": 2, "step_timeout_seconds": 300})

    def test_strict_json_and_integer_validation(self):
        bad = request()
        bad["criteria"]["thresholds"]["x"] = float("nan")
        with self.assertRaises(InvalidRoundRequestError):
            RoundConfig.from_request(bad)
        with self.assertRaises(InvalidRoundRequestError):
            RoundConfig.from_request(request(limits={"max_attempts_per_step": True}))

    def test_invalid_requests_rejected(self):
        mgr = make_manager()
        cases = []
        bad = request(); del bad["versions"]["model_id"]; cases.append(bad)
        cases.append(request(extra_field=1))
        cases.append({k: v for k, v in REQUEST.items() if k != "criteria"})
        cases.append(request(limits={"max_attempts_per_step": 0}))
        cases.append(request(contract_version="9.9.9"))
        cases.append(request(task_id="../evil"))
        bad = request(); bad["detection"]["rule_language"] = "kql"; cases.append(bad)
        bad = request(); bad["benign_constraints"]["allowed_scenario_families"] = ["malware_dev"]; cases.append(bad)
        bad = request(); bad["benign_constraints"]["max_workflow_steps"] = 11; cases.append(bad)
        bad = request(); del bad["dataset"]["evaluation_set_id"]; cases.append(bad)
        bad = request(); bad["criteria"]["thresholds"] = {}; cases.append(bad)
        cases.append(request(permitted_evidence_refs=[{"evidence_id": "e1", "evidence_type": "model_claim"}]))
        for case in cases:
            with self.assertRaises(InvalidRoundRequestError, msg=str(case)[:80]):
                mgr.create_round(case)

    def test_detection_text_limits_follow_the_schema(self):
        limits = {
            "description": contracts.MAX_DESCRIPTION_LENGTH,
            "logic_summary": contracts.MAX_LOGIC_SUMMARY_LENGTH,
            "rule_text": contracts.MAX_RULE_TEXT_LENGTH,
        }
        for name, limit in limits.items():
            at_limit = request()
            at_limit["detection"][name] = "a" * limit
            RoundConfig.from_request(at_limit)  # exactly the maximum is fine
            over = request()
            over["detection"][name] = "a" * (limit + 1)
            with self.assertRaises(InvalidRoundRequestError, msg=name) as ctx:
                RoundConfig.from_request(over)
            self.assertIn(f"detection.{name}", ctx.exception.problems[0])
        # a derived red_input can never carry text longer than red_input allows
        red_input = RoundConfig.from_request(request()).to_red_input()
        self.assertLessEqual(len(red_input["detection"]["logic_summary"]), contracts.MAX_LOGIC_SUMMARY_LENGTH)

    def test_missing_fields_are_missing_information_other_problems_are_validation(self):
        with self.assertRaises(InvalidRoundRequestError) as missing:
            RoundConfig.from_request({k: v for k, v in REQUEST.items() if k != "criteria"})
        self.assertEqual(missing.exception.error_category, "missing_information")
        self.assertEqual(missing.exception.details["missing_fields"], ["criteria"])
        with self.assertRaises(InvalidRoundRequestError) as invalid:
            RoundConfig.from_request(request(contract_version="9.9.9"))
        self.assertEqual(invalid.exception.error_category, "validation")

    def test_same_request_same_fingerprint(self):
        a = make_manager().create_round(REQUEST)
        b = make_manager().create_round(copy.deepcopy(REQUEST))
        self.assertEqual(a.config_fingerprint, b.config_fingerprint)

    def test_pinned_versions_collects_every_reference(self):
        pinned = make_manager().create_round(REQUEST).config.pinned_versions()
        self.assertEqual(
            pinned,
            {
                "contracts": "0.1.0",
                "red_prompt": "red-system@0.1.0",
                "blue_prompt": "blue-system@0.1.0",
                "model_id": "hosted-model-x",
                "rule_version": "3.2.0",
                "dataset_version": "2026.11.1",
                "evaluation_set_id": "evalset-01",
                "criteria_id": "criteria-001",
                "criteria_version": "1.0",
            },
        )

    def test_red_input_hides_rule_text_and_carries_the_pinned_prompt(self):
        red_input = RoundConfig.from_request(request()).to_red_input()
        self.assertNotIn("rule_text", red_input["detection"])
        self.assertNotIn("rule_language", red_input["detection"])
        self.assertEqual(red_input["prompt_version"], "red-system@0.1.0")
        self.assertEqual(red_input["task_id"], "task-001")


class WorkflowTests(unittest.TestCase):
    def test_full_happy_path(self):
        mgr = make_manager()
        rid = open_round(mgr)
        run_to_judged(mgr, rid)
        rec = mgr.complete(rid, "pass", "feedback://rec-1")
        self.assertEqual(rec.state, RoundState.COMPLETED)
        self.assertEqual(rec.outcome, "pass")
        self.assertIsNone(rec.error)
        self.assertIsNotNone(rec.closed_at)
        self.assertEqual([t.sequence for t in rec.transitions], list(range(1, 9)))
        self.assertEqual(rec.artifacts["feedback_record"], "feedback://rec-1")
        self.assertEqual(rec.artifacts["judge_result"], "audit://task-001/judge")
        mgr.verify_integrity(rid)

    def test_reject_still_completes(self):
        mgr = make_manager()
        rid = open_round(mgr)
        run_to_judged(mgr, rid)
        self.assertEqual(mgr.complete(rid, "reject", "feedback://x").outcome, "reject")

    def test_judge_decision_is_case_insensitive(self):
        mgr = make_manager()
        rid = open_round(mgr)
        run_to_judged(mgr, rid)
        self.assertEqual(mgr.complete(rid, "PASS", "feedback://x").outcome, "pass")

    def test_judge_inconclusive_closes_inconclusive_without_an_error(self):
        mgr = make_manager()
        rid = open_round(mgr)
        run_to_judged(mgr, rid)
        rec = mgr.complete(rid, "inconclusive", "feedback://x")
        self.assertEqual(rec.state, RoundState.INCONCLUSIVE)
        self.assertEqual(rec.outcome, "inconclusive")
        self.assertIsNone(mgr.error_response(rid))  # a judge result, not an error
        self.assertEqual(rec.artifacts["feedback_record"], "feedback://x")
        mgr.verify_integrity(rid)

    def test_cannot_skip_or_reorder(self):
        mgr = make_manager()
        rid = open_round(mgr)
        with self.assertRaises(InvalidTransitionError):
            mgr.advance(rid, RoundState.BLUE_PROPOSED, artifacts=STATE_ARTIFACTS[RoundState.BLUE_PROPOSED])
        mgr.advance(rid, RoundState.RED_PROPOSED, artifacts=STATE_ARTIFACTS[RoundState.RED_PROPOSED])
        with self.assertRaises(InvalidTransitionError):
            mgr.advance(rid, RoundState.CREATED)

    def test_terminal_exits_need_dedicated_methods(self):
        mgr = make_manager()
        rid = open_round(mgr)
        for target in (RoundState.FAILED, RoundState.INCONCLUSIVE, RoundState.COMPLETED):
            with self.assertRaises(InvalidTransitionError):
                mgr.advance(rid, target)

    def test_complete_only_from_judged(self):
        mgr = make_manager()
        rid = open_round(mgr)
        with self.assertRaises(InvalidTransitionError):
            mgr.complete(rid, "pass", "feedback://x")

    def test_complete_rejects_bad_input(self):
        mgr = make_manager()
        rid = open_round(mgr)
        run_to_judged(mgr, rid)
        with self.assertRaises(InvalidArgumentError):
            mgr.complete(rid, "maybe", "feedback://x")
        with self.assertRaises(InvalidArgumentError):
            mgr.complete(rid, "pass", "")

    def test_unknown_round(self):
        with self.assertRaises(RoundNotFoundError):
            make_manager().get_round("nope")


class ArtifactTests(unittest.TestCase):
    def test_each_forward_state_requires_its_contract_messages(self):
        mgr = make_manager()
        rid = open_round(mgr)
        with self.assertRaises(MissingArtifactError) as ctx:
            mgr.advance(rid, RoundState.RED_PROPOSED)
        self.assertEqual(ctx.exception.error_category, "missing_information")
        self.assertEqual(ctx.exception.details["missing_artifacts"], ["red_proposal"])
        self.assertEqual(mgr.get_round(rid).state, RoundState.CREATED)

    def test_candidate_state_needs_rule_and_candidate_matches(self):
        mgr = make_manager()
        rid = open_round(mgr)
        advance_to(mgr, rid, RoundState.BLUE_PROPOSED)
        with self.assertRaises(MissingArtifactError):
            mgr.advance(rid, RoundState.CANDIDATE_EXECUTED, artifacts={"candidate_rule": "evidence://c"})

    def test_unknown_and_misplaced_artifacts_rejected(self):
        mgr = make_manager()
        rid = open_round(mgr)
        with self.assertRaises(InvalidArgumentError):
            mgr.advance(rid, RoundState.RED_PROPOSED, artifacts={"red_proposal": "a", "proposal": "b"})
        with self.assertRaises(InvalidArgumentError):  # blue_proposal does not belong to the red step
            mgr.advance(rid, RoundState.RED_PROPOSED, artifacts={"red_proposal": "a", "blue_proposal": "b"})
        with self.assertRaises(InvalidArgumentError):
            mgr.advance(rid, RoundState.RED_PROPOSED, artifacts={"red_proposal": " "})

    def test_artifact_cannot_be_recorded_twice(self):
        # baseline_match_set is allowed at evidence_verified and candidate_executed, but only once.
        mgr = make_manager()
        rid = open_round(mgr)
        mgr.advance(rid, RoundState.RED_PROPOSED, artifacts=STATE_ARTIFACTS[RoundState.RED_PROPOSED])
        mgr.advance(rid, RoundState.TELEMETRY_COLLECTED)
        mgr.advance(
            rid,
            RoundState.EVIDENCE_VERIFIED,
            artifacts={**STATE_ARTIFACTS[RoundState.EVIDENCE_VERIFIED], "baseline_match_set": "evidence://b"},
        )
        mgr.advance(rid, RoundState.BLUE_PROPOSED, artifacts=STATE_ARTIFACTS[RoundState.BLUE_PROPOSED])
        with self.assertRaises(InvalidArgumentError):
            mgr.advance(rid, RoundState.CANDIDATE_EXECUTED, artifacts=STATE_ARTIFACTS[RoundState.CANDIDATE_EXECUTED])

    def test_judged_requires_judge_result_and_completion_requires_feedback(self):
        mgr = make_manager()
        rid = open_round(mgr)
        advance_to(mgr, rid, RoundState.CANDIDATE_EXECUTED)
        with self.assertRaises(MissingArtifactError):
            mgr.advance(rid, RoundState.JUDGED)
        self.assertIn("feedback_record", REQUIRED_ARTIFACTS[RoundState.COMPLETED])
        self.assertIn("feedback_record", ALLOWED_ARTIFACTS[RoundState.INCONCLUSIVE])


class FailureTests(unittest.TestCase):
    def test_fail_stores_a_contract_style_error_and_closes(self):
        mgr = make_manager()
        rid = open_round(mgr)
        mgr.advance(rid, RoundState.RED_PROPOSED, artifacts=STATE_ARTIFACTS[RoundState.RED_PROPOSED])
        rec = mgr.fail(rid, "dependency", "splunk unavailable", retryable=True, details={"dependency": "splunk"})
        self.assertEqual(rec.state, RoundState.FAILED)
        err = rec.error
        self.assertEqual(err["contract_version"], "0.1.0")
        self.assertEqual(err["error_id"], "err-001")
        self.assertEqual(err["category"], "dependency")
        self.assertEqual(err["source_component"], "01_orchestrator")
        self.assertEqual(err["task_id"], "task-001")
        self.assertEqual(err["details"], {"dependency": "splunk", "failed_in_state": "red_proposed"})
        self.assertTrue(err["retryable"])
        self.assertEqual(mgr.error_response(rid)["message"], "splunk unavailable")
        mgr.verify_integrity(rid)

    def test_closed_round_is_immutable(self):
        mgr = make_manager()
        rid = open_round(mgr)
        mgr.fail(rid, "validation", "malformed red output")
        with self.assertRaises(RoundClosedError):
            mgr.advance(rid, RoundState.RED_PROPOSED, artifacts=STATE_ARTIFACTS[RoundState.RED_PROPOSED])
        with self.assertRaises(RoundClosedError):
            mgr.fail(rid, "validation", "again")

    def test_inconclusive_for_missing_evidence_is_missing_information(self):
        mgr = make_manager()
        rid = open_round(mgr)
        advance_to(mgr, rid, RoundState.TELEMETRY_COLLECTED)
        out = mgr.mark_inconclusive(rid, "no reviewed labels", details={"missing": ["labels"]})
        self.assertEqual(out.state, RoundState.INCONCLUSIVE)
        self.assertEqual(out.outcome, "inconclusive")
        self.assertEqual(out.error["category"], "missing_information")
        self.assertEqual(out.error["details"]["missing"], ["labels"])
        mgr.verify_integrity(rid)

    def test_unknown_error_category(self):
        mgr = make_manager()
        rid = open_round(mgr)
        for category in ("bogus", "retry", "conflict", "integrity"):  # not contract categories
            with self.assertRaises(InvalidArgumentError):
                mgr.fail(rid, category, "x")
        with self.assertRaises(InvalidArgumentError):
            mgr.mark_inconclusive(rid, "x", category="bogus")


class RetryTimeoutTests(unittest.TestCase):
    def test_retries_bounded_and_fail_round_with_the_last_error_category(self):
        mgr = make_manager()
        rid = open_round(mgr, limits={"max_attempts_per_step": 2})
        self.assertEqual(mgr.begin_attempt(rid), 1)
        first = mgr.finish_attempt(
            rid, "failed", error="temporary dependency failure", error_category="dependency", raw_output_ref="audit://attempt/1"
        )
        self.assertEqual(first.state, RoundState.CREATED)
        self.assertEqual(mgr.begin_attempt(rid), 2)
        rec = mgr.finish_attempt(
            rid, "failed", error="second failure", error_category="dependency", raw_output_ref="audit://attempt/2"
        )
        self.assertEqual(rec.state, RoundState.FAILED)
        self.assertEqual(rec.error["category"], "dependency")
        self.assertEqual(rec.error["details"]["reason"], "retry_exhausted")
        self.assertFalse(rec.error["retryable"])
        self.assertEqual([a.outcome for a in rec.attempt_log], ["failed", "failed"])
        self.assertEqual([a.error_category for a in rec.attempt_log], ["dependency", "dependency"])
        self.assertEqual(rec.attempt_log[0].raw_output_ref, "audit://attempt/1")
        mgr.verify_integrity(rid)
        with self.assertRaises(RoundClosedError):
            mgr.begin_attempt(rid)

    def test_attempt_error_category_defaults_to_internal_and_is_validated(self):
        mgr = make_manager()
        rid = open_round(mgr, limits={"max_attempts_per_step": 1})
        mgr.begin_attempt(rid)
        with self.assertRaises(InvalidArgumentError):
            mgr.finish_attempt(rid, "failed", error="x", error_category="retry")
        rec = mgr.finish_attempt(rid, "failed", error="boom")
        self.assertEqual(rec.error["category"], "internal")

    def test_begin_attempt_past_the_limit_fails_the_round(self):
        mgr = make_manager()
        rid = open_round(mgr, limits={"max_attempts_per_step": 1})
        mgr.begin_attempt(rid)
        mgr.finish_attempt(rid, "succeeded")
        with self.assertRaises(RetryExhaustedError) as ctx:
            mgr.begin_attempt(rid)
        self.assertEqual(ctx.exception.error_category, "internal")
        rec = mgr.get_round(rid)
        self.assertEqual(rec.state, RoundState.FAILED)
        self.assertEqual(rec.error["details"]["reason"], "retry_exhausted")
        mgr.verify_integrity(rid)

    def test_attempts_reset_on_new_step(self):
        mgr = make_manager()
        rid = open_round(mgr, limits={"max_attempts_per_step": 1})
        mgr.begin_attempt(rid)
        mgr.finish_attempt(rid, "succeeded", raw_output_ref="audit://red")
        mgr.advance(rid, RoundState.RED_PROPOSED, artifacts=STATE_ARTIFACTS[RoundState.RED_PROPOSED])
        self.assertEqual(mgr.begin_attempt(rid), 1)

    def test_timeout(self):
        clock = FakeClock()
        mgr = make_manager(clock=clock)
        rid = open_round(mgr, limits={"step_timeout_seconds": 60})
        clock.tick(30)
        self.assertFalse(mgr.enforce_timeout(rid))
        clock.tick(31)
        self.assertTrue(mgr.is_timed_out(rid))
        self.assertTrue(mgr.enforce_timeout(rid))
        rec = mgr.get_round(rid)
        self.assertEqual(rec.state, RoundState.FAILED)
        self.assertEqual(rec.error["category"], "timeout")
        self.assertTrue(rec.error["retryable"])

    def test_timeout_clock_resets_on_advance(self):
        clock = FakeClock()
        mgr = make_manager(clock=clock)
        rid = open_round(mgr, limits={"step_timeout_seconds": 60})
        clock.tick(50)
        mgr.advance(rid, RoundState.RED_PROPOSED, artifacts=STATE_ARTIFACTS[RoundState.RED_PROPOSED])
        clock.tick(50)
        self.assertFalse(mgr.is_timed_out(rid))

    def test_complete_honours_the_step_timeout(self):
        clock = FakeClock()
        mgr = make_manager(clock=clock)
        rid = open_round(mgr, limits={"step_timeout_seconds": 60})
        run_to_judged(mgr, rid)
        clock.tick(60)  # the feedback record arrives too late
        with self.assertRaises(RoundTimedOutError):
            mgr.complete(rid, "pass", "feedback://late")
        rec = mgr.get_round(rid)
        self.assertEqual(rec.state, RoundState.FAILED)
        self.assertEqual(rec.error["category"], "timeout")
        self.assertEqual(rec.error["details"]["failed_in_state"], "judged")
        self.assertNotIn("feedback_record", rec.artifacts)
        mgr.verify_integrity(rid)

    def test_complete_just_inside_the_timeout_succeeds(self):
        clock = FakeClock()
        mgr = make_manager(clock=clock)
        rid = open_round(mgr, limits={"step_timeout_seconds": 60})
        run_to_judged(mgr, rid)
        clock.tick(59)
        self.assertEqual(mgr.complete(rid, "pass", "feedback://ok").state, RoundState.COMPLETED)

    def test_late_advance_fails_round_and_closed_timeout_poll_is_safe(self):
        clock = FakeClock()
        mgr = make_manager(clock=clock)
        rid = open_round(mgr, limits={"step_timeout_seconds": 10})
        clock.tick(10)
        with self.assertRaises(RoundTimedOutError):
            mgr.advance(rid, RoundState.RED_PROPOSED, artifacts=STATE_ARTIFACTS[RoundState.RED_PROPOSED])
        self.assertEqual(mgr.get_round(rid).state, RoundState.FAILED)
        self.assertFalse(mgr.is_timed_out(rid))
        self.assertFalse(mgr.enforce_timeout(rid))

    def test_attempt_result_rejects_non_json_error_details(self):
        mgr = make_manager()
        rid = open_round(mgr)
        with self.assertRaises(InvalidArgumentError):
            mgr.fail(rid, "internal", "bad details", details={"bad": {1, 2}})

    def test_clock_regression_keeps_history_valid(self):
        clock = FakeClock()
        mgr = make_manager(clock=clock)
        rid = open_round(mgr)
        clock.tick(-5)
        mgr.advance(rid, RoundState.RED_PROPOSED, artifacts=STATE_ARTIFACTS[RoundState.RED_PROPOSED])
        mgr.verify_integrity(rid)


class PersistenceTests(unittest.TestCase):
    def test_json_store_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = make_manager(store=JsonFileRoundStore(tmp))
            rid = open_round(mgr)
            mgr.begin_attempt(rid)
            mgr.finish_attempt(rid, "succeeded", raw_output_ref="audit://red/raw")
            run_to_judged(mgr, rid)
            mgr.complete(rid, "pass", "feedback://x")
            # A brand-new manager on the same folder sees the same round.
            mgr2 = RoundManager(JsonFileRoundStore(tmp))
            rec = mgr2.get_round(rid)
            self.assertEqual(rec.state, RoundState.COMPLETED)
            self.assertEqual(len(rec.transitions), 8)
            self.assertEqual(rec.attempt_log[0].raw_output_ref, "audit://red/raw")
            self.assertEqual(rec.transitions[5].artifacts["candidate_rule"], "evidence://task-001/candidate")
            mgr2.verify_integrity(rid)
            self.assertEqual(JsonFileRoundStore(tmp).list_ids(), [rid])

    def test_unsafe_id_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(Exception):
                JsonFileRoundStore(tmp).load("../evil")

    def test_corrupt_json_is_integrity_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = JsonFileRoundStore(tmp)
            rid = open_round(make_manager(store=store))
            with open(os.path.join(tmp, f"{rid}.json"), "w", encoding="utf-8") as fh:
                fh.write("{")
            with self.assertRaises(IntegrityError):
                store.load(rid)

    def test_failed_json_serialization_does_not_bump_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = JsonFileRoundStore(tmp)
            rid = open_round(make_manager(store=store))
            rec = store.load(rid)
            old_revision = rec.revision
            rec.error = {"unsupported": {1, 2}}
            with self.assertRaises(IntegrityError):
                store.save(rec)
            self.assertEqual(rec.revision, old_revision)

    def test_stale_write_detected(self):
        store = InMemoryRoundStore()
        mgr = make_manager(store=store)
        rid = open_round(mgr)
        stale = store.load(rid)
        mgr.advance(rid, RoundState.RED_PROPOSED, artifacts=STATE_ARTIFACTS[RoundState.RED_PROPOSED])
        with self.assertRaises(ConcurrencyError):
            store.save(stale)

    def test_tampered_config_detected(self):
        store = InMemoryRoundStore()
        mgr = make_manager(store=store)
        rid = open_round(mgr)
        rec = store.load(rid)
        rec.config_fingerprint = "0" * 64
        store.save(rec)
        with self.assertRaises(IntegrityError):
            mgr.verify_integrity(rid)

    def test_tampered_outcome_detected(self):
        store = InMemoryRoundStore()
        mgr = make_manager(store=store)
        rid = open_round(mgr)
        rec = store.load(rid)
        rec.outcome = "pass"
        store.save(rec)
        with self.assertRaises(IntegrityError):
            mgr.verify_integrity(rid)

    def test_tampered_artifact_index_detected(self):
        store = InMemoryRoundStore()
        mgr = make_manager(store=store)
        rid = open_round(mgr)
        mgr.advance(rid, RoundState.RED_PROPOSED, artifacts=STATE_ARTIFACTS[RoundState.RED_PROPOSED])
        rec = store.load(rid)
        rec.artifacts["red_proposal"] = "ref://tampered"
        store.save(rec)
        with self.assertRaises(IntegrityError):
            mgr.verify_integrity(rid)

    def test_missing_required_artifact_in_history_detected(self):
        store = InMemoryRoundStore()
        mgr = make_manager(store=store)
        rid = open_round(mgr)
        mgr.advance(rid, RoundState.RED_PROPOSED, artifacts=STATE_ARTIFACTS[RoundState.RED_PROPOSED])
        rec = store.load(rid)
        rec.transitions[-1] = type(rec.transitions[-1])(**{**rec.transitions[-1].__dict__, "artifacts": {}})
        rec.artifacts = {}
        store.save(rec)
        with self.assertRaises(IntegrityError):
            mgr.verify_integrity(rid)

    def test_tampered_error_detected(self):
        store = InMemoryRoundStore()
        mgr = make_manager(store=store)
        rid = open_round(mgr)
        mgr.fail(rid, "internal", "boom")
        rec = store.load(rid)
        rec.error["category"] = "retry"  # not an error_response category
        store.save(rec)
        with self.assertRaises(IntegrityError):
            mgr.verify_integrity(rid)


try:
    import pymongo
    from pymongo.errors import DuplicateKeyError, ServerSelectionTimeoutError, WriteError
except ImportError:
    pymongo = None


@lru_cache(maxsize=1)
def _mongo_backend():
    """'mongodb' if a server answers (AUTOSOC_MONGO_URI), else 'mongomock' if installed, else None."""
    if pymongo is None:
        return None
    try:
        client = pymongo.MongoClient(
            os.environ.get("AUTOSOC_MONGO_URI", "mongodb://localhost:27017"), serverSelectionTimeoutMS=500
        )
        client.admin.command("ping")
        client.close()
        return "mongodb"
    except Exception:
        pass
    try:
        import mongomock  # noqa: F401

        return "mongomock"
    except ImportError:
        return None


@unittest.skipUnless(_mongo_backend(), "pymongo (and a MongoDB server or mongomock) is not installed")
class MongoStoreTests(unittest.TestCase):
    """The same store behaviour against MongoDB (a real server when reachable, otherwise mongomock)."""

    def setUp(self):
        self.db_name = f"autosoc_test_rounds_{uuid.uuid4().hex[:8]}"
        if _mongo_backend() == "mongodb":
            self.client = pymongo.MongoClient(
                os.environ.get("AUTOSOC_MONGO_URI", "mongodb://localhost:27017"), serverSelectionTimeoutMS=2000
            )
        else:
            import mongomock

            self.client = mongomock.MongoClient()
        self.coll = self.client[self.db_name]["rounds"]
        self.store = MongoRoundStore(self.coll)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        self.client.drop_database(self.db_name)
        self.client.close()

    def test_full_round_survives_a_new_manager_and_store(self):
        mgr = make_manager(store=self.store)
        rid = open_round(mgr)
        mgr.begin_attempt(rid)
        mgr.finish_attempt(rid, "succeeded", raw_output_ref="audit://red/raw")
        run_to_judged(mgr, rid)
        mgr.complete(rid, "pass", "feedback://x")
        again = RoundManager(MongoRoundStore(self.coll))
        rec = again.get_round(rid)
        self.assertEqual(rec.state, RoundState.COMPLETED)
        self.assertEqual(len(rec.transitions), 8)
        self.assertEqual(rec.attempt_log[0].raw_output_ref, "audit://red/raw")
        self.assertEqual(rec.transitions[5].artifacts["candidate_rule"], "evidence://task-001/candidate")
        again.verify_integrity(rid)
        self.assertEqual(self.store.list_ids(), [rid])

    def test_document_layout(self):
        rid = open_round(make_manager(store=self.store))
        doc = self.coll.find_one({"_id": rid})
        self.assertEqual(doc["round_id"], rid)
        self.assertEqual(doc["task_id"], rid)
        self.assertEqual(doc["revision"], 1)
        self.assertEqual(doc["config"]["contract_version"], "0.1.0")
        self.assertEqual(self.store.load(rid).revision, 1)

    def test_load_missing_returns_none_and_list_is_sorted(self):
        self.assertIsNone(self.store.load("nope"))
        mgr = make_manager(store=self.store)
        for task_id in ("task-b", "task-a"):
            mgr.create_round(request(task_id=task_id))
        self.assertEqual(self.store.list_ids(), ["task-a", "task-b"])

    def test_stale_write_detected(self):
        mgr = make_manager(store=self.store)
        rid = open_round(mgr)
        stale = self.store.load(rid)
        mgr.advance(rid, RoundState.RED_PROPOSED, artifacts=STATE_ARTIFACTS[RoundState.RED_PROPOSED])
        with self.assertRaises(ConcurrencyError):
            self.store.save(stale)
        self.assertEqual(stale.revision, 1)  # a failed save does not bump the revision

    def test_creating_the_same_round_twice_is_rejected(self):
        mgr = make_manager(store=self.store)
        rid = open_round(mgr)
        with self.assertRaises(DuplicateRoundError):
            mgr.create_round(REQUEST)
        with self.assertRaises(ConcurrencyError):
            self.store.save(unsaved_record())  # same round id, never loaded: the insert collides
        self.assertEqual(self.coll.count_documents({"_id": rid}), 1)

    def test_updating_a_round_that_was_never_stored_is_rejected(self):
        rec = unsaved_record()
        rec.revision = 3
        with self.assertRaises(ConcurrencyError):
            self.store.save(rec)

    def test_exactly_one_of_two_concurrent_writers_wins_without_any_lock(self):
        mgr = make_manager(store=self.store)
        rid = open_round(mgr)
        stale_a, stale_b = self.store.load(rid), self.store.load(rid)
        barrier = threading.Barrier(2)
        results = []

        def save_stale(record):
            barrier.wait()
            try:
                self.store.save(record)
                results.append("saved")
            except ConcurrencyError:
                results.append("stale")

        threads = [threading.Thread(target=save_stale, args=(r,)) for r in (stale_a, stale_b)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertCountEqual(results, ["saved", "stale"])
        self.assertEqual(self.store.load(rid).revision, 2)

    def test_unsafe_ids_rejected(self):
        for bad in ("../evil", "a b", "", None, {"$ne": 1}, 5):
            with self.assertRaises(RoundManagementError):
                self.store.load(bad)

    def test_corrupt_document_is_integrity_error(self):
        self.coll.insert_one({"_id": "broken", "round_id": "broken", "revision": 1})
        with self.assertRaises(IntegrityError):
            self.store.load("broken")

    def test_non_json_values_are_rejected_and_do_not_bump_the_revision(self):
        rid = open_round(make_manager(store=self.store))
        rec = self.store.load(rid)
        old = rec.revision
        rec.error = {"bad": float("nan")}
        with self.assertRaises(IntegrityError):
            self.store.save(rec)
        self.assertEqual(rec.revision, old)

    def test_from_repository_uses_the_repository_database(self):
        class Repo:
            db = self.client[self.db_name]

        store = MongoRoundStore.from_repository(Repo())
        open_round(make_manager(store=store))
        self.assertEqual(self.coll.count_documents({}), 1)

    def test_ensure_indexes(self):
        self.store.ensure_indexes()
        self.store.ensure_indexes()  # idempotent
        self.assertIn("ix_state", self.coll.index_information())
        self.assertIn("ix_task_id", self.coll.index_information())


@unittest.skipIf(pymongo is None, "pymongo is not installed")
class MongoStoreFailureTests(unittest.TestCase):
    """Datastore failures surface as the right orchestrator errors."""

    class BrokenCollection:
        def __init__(self, error):
            self.error = error

        def __getattr__(self, name):
            def fail(*args, **kwargs):
                raise self.error

            return fail

    def store(self, error):
        return MongoRoundStore(self.BrokenCollection(error))

    def test_unreachable_server_is_a_retryable_dependency_error(self):
        store = self.store(ServerSelectionTimeoutError("localhost:27017: connection refused"))
        record = unsaved_record()
        for call in (lambda: store.load("task-001"), store.list_ids, lambda: store.save(record), store.ensure_indexes):
            with self.assertRaises(StoreUnavailableError) as ctx:
                call()
            self.assertEqual(ctx.exception.error_category, "dependency")
            self.assertTrue(ctx.exception.retryable)
            self.assertEqual(ctx.exception.details["error_type"], "ServerSelectionTimeoutError")
        self.assertEqual(record.revision, 0)  # nothing was saved, nothing was bumped

    def test_rejected_documents_are_integrity_errors(self):
        record = unsaved_record()
        with self.assertRaises(IntegrityError):
            self.store(WriteError("key must not contain '.'")).save(record)
        self.assertEqual(record.revision, 0)

    def test_duplicate_key_is_a_concurrency_error(self):
        record = unsaved_record()
        with self.assertRaises(ConcurrencyError):
            self.store(DuplicateKeyError("E11000 duplicate key")).save(record)

    def test_store_unavailable_maps_to_a_contract_error(self):
        error = StoreUnavailableError("down", {"error_type": "AutoReconnect"}).to_error_response("task-001")
        self.assertEqual(error["category"], "dependency")
        self.assertTrue(error["retryable"])


class ErrorResponseTests(unittest.TestCase):
    """Everything the orchestrator reports as an error uses the error_response shape."""

    REQUIRED = {"contract_version", "error_id", "category", "source_component", "message", "retryable"}
    ALLOWED = REQUIRED | {"task_id", "details", "timestamp"}

    def assert_shape(self, error):
        self.assertTrue(self.REQUIRED <= set(error), error)
        self.assertTrue(set(error) <= self.ALLOWED, error)
        self.assertIn(error["category"], contracts.ERROR_CATEGORIES)
        self.assertEqual(error["source_component"], "01_orchestrator")
        self.assertIsInstance(error["retryable"], bool)

    def test_every_exception_maps_to_a_contract_category(self):
        for exc in (
            RoundManagementError("x"),
            InvalidRoundRequestError(["p"]),
            InvalidTransitionError("x"),
            InvalidArgumentError("x"),
            MissingArtifactError("x"),
            RoundNotFoundError("x"),
            DuplicateRoundError("x"),
            RoundClosedError("x"),
            RetryExhaustedError("x"),
            RetryExhaustedError("x", category="dependency"),
            RoundTimedOutError("x"),
            ConcurrencyError("x"),
            IntegrityError("x"),
            StoreUnavailableError("x"),
        ):
            self.assert_shape(exc.to_error_response("task-001"))

    def test_stored_errors_have_the_contract_shape(self):
        for build in (
            lambda m, r: m.fail(r, "validation", "bad"),
            lambda m, r: m.mark_inconclusive(r, "no labels"),
        ):
            mgr = make_manager()
            rid = open_round(mgr)
            self.assert_shape(build(mgr, rid).error)

    def test_make_error_response_rejects_bad_input(self):
        bad_calls = [
            dict(category="retry", message="x"),
            dict(category="internal", message=" "),
            dict(category="internal", message="x", error_id=""),
            dict(category="internal", message="x", error_id=123),
            dict(category="internal", message="x", task_id=""),
            dict(category="internal", message="x", retryable="yes"),
            dict(category="internal", message="x", retryable=1),
            dict(category="internal", message="x", details=["not", "an", "object"]),
            dict(category="internal", message="x", details={"bad": {1, 2}}),
            dict(category="internal", message="x", details={"bad": float("nan")}),
            dict(category="internal", message="x", timestamp="yesterday"),
            dict(category="internal", message="x", timestamp="2026-11-17T12:00:00"),  # no time zone
            dict(category="internal", message="x", timestamp=1700000000),
        ]
        for kwargs in bad_calls:
            with self.assertRaises(ValueError, msg=str(kwargs)):
                make_error_response(**kwargs)

    def test_make_error_response_accepts_valid_optionals_and_copies_details(self):
        details = {"nested": {"items": [1, 2]}}
        out = make_error_response(
            "dependency", "x", task_id="t-1", retryable=True, details=details,
            error_id="e-1", timestamp="2026-11-17T12:00:00Z",
        )
        details["nested"]["items"].append(3)  # later mutation must not leak into the response
        self.assertEqual(out["details"], {"nested": {"items": [1, 2]}})
        self.assertEqual(out["error_id"], "e-1")
        json.dumps(out, allow_nan=False)  # always serialisable
        make_error_response("internal", "x", timestamp="2026-11-17T12:00:00+02:00")

    def test_a_bad_error_id_factory_is_a_round_management_error(self):
        mgr = RoundManager(InMemoryRoundStore(), clock=FakeClock(), error_id_factory=lambda: "")
        rid = open_round(mgr)
        with self.assertRaises(RoundManagementError):
            mgr.fail(rid, "internal", "boom")
        self.assertEqual(mgr.get_round(rid).state, RoundState.CREATED)  # nothing half-written


@unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema is not installed")
class ContractTests(unittest.TestCase):
    """Check round management against the real schema files (needs jsonschema)."""

    @classmethod
    def setUpClass(cls):
        schemas = {}
        paths = list(CONTRACTS_DIR.rglob("*.schema.json")) + [
            REPO_ROOT / "02_red_role" / "interfaces" / "inputs" / "red_input.schema.json"
        ]
        for path in paths:
            schema = json.loads(path.read_text(encoding="utf-8"))
            schemas[schema["$id"]] = schema
        cls.schemas = schemas
        cls.registry = Registry().with_resources(
            [(uri, Resource.from_contents(s, DRAFT202012)) for uri, s in schemas.items()]
        )

    def errors(self, uri, doc):
        return list(Draft202012Validator(self.schemas[uri], registry=self.registry).iter_errors(doc))

    def example(self, name):
        return json.loads((CONTRACTS_DIR / "round_request" / "examples" / name).read_text(encoding="utf-8"))

    def test_mirrored_constants_match_the_schemas(self):
        rr = self.schemas["autosoc://contracts/round_request/0.1.0"]["properties"]
        constraints = rr["benign_constraints"]["properties"]
        self.assertEqual(tuple(constraints["allowed_scenario_families"]["items"]["enum"]), contracts.SCENARIO_FAMILIES)
        self.assertEqual(tuple(constraints["allowed_actions"]["items"]["enum"]), contracts.ALLOWED_ACTIONS)
        self.assertEqual(tuple(rr["detection"]["properties"]["rule_language"]["enum"]), contracts.RULE_LANGUAGES)
        err = self.schemas["autosoc://contracts/error_response/0.1.0"]["properties"]
        self.assertEqual(tuple(err["category"]["enum"]), contracts.ERROR_CATEGORIES)
        self.assertEqual(err["contract_version"]["const"], contracts.CONTRACT_VERSION)
        ref = self.schemas["autosoc://contracts/telemetry_evidence/evidence_reference/0.1.0"]["properties"]
        self.assertEqual(tuple(ref["evidence_type"]["enum"]), contracts.EVIDENCE_TYPES)
        red = self.schemas["autosoc://red_role/interfaces/inputs/red_input/0.1.0"]["properties"]["benign_constraints"]["properties"]
        self.assertEqual(tuple(red["allowed_scenario_families"]["items"]["enum"]), contracts.SCENARIO_FAMILIES)
        self.assertEqual(tuple(red["allowed_actions"]["items"]["enum"]), contracts.ALLOWED_ACTIONS)

    def test_round_request_examples_agree_with_round_config(self):
        uri = "autosoc://contracts/round_request/0.1.0"
        valid = self.example("valid_round_request.json")
        self.assertEqual(self.errors(uri, valid), [])
        RoundConfig.from_request(valid)
        invalid = self.example("invalid_round_request.json")
        self.assertNotEqual(self.errors(uri, invalid), [])
        with self.assertRaises(InvalidRoundRequestError):
            RoundConfig.from_request(invalid)

    def test_mirrored_text_limits_match_the_schema(self):
        detection = self.schemas["autosoc://contracts/round_request/0.1.0"]["properties"]["detection"]["properties"]
        self.assertEqual(detection["description"]["maxLength"], contracts.MAX_DESCRIPTION_LENGTH)
        self.assertEqual(detection["logic_summary"]["maxLength"], contracts.MAX_LOGIC_SUMMARY_LENGTH)
        self.assertEqual(detection["rule_text"]["maxLength"], contracts.MAX_RULE_TEXT_LENGTH)

    def test_round_config_never_accepts_what_the_schema_rejects(self):
        uri = "autosoc://contracts/round_request/0.1.0"
        red_uri = "autosoc://red_role/interfaces/inputs/red_input/0.1.0"

        def mutated(path, value):
            doc = request()
            target = doc
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            return doc

        cases = [mutated(("detection", name), "a" * n) for name, limit in
                 (("description", 1000), ("logic_summary", 4000), ("rule_text", 20000)) for n in (limit, limit + 1)]
        cases += [
            mutated(("benign_constraints", "max_workflow_steps"), n) for n in (0, 1, 10, 11)
        ] + [
            mutated(("limits",), {"max_attempts_per_step": n}) for n in (0, 1)
        ] + [
            mutated(("dataset", "evaluation_set_checksum"), v) for v in ("a" * 64, "g" * 64, "a" * 63)
        ] + [
            mutated(("criteria", "thresholds"), v) for v in ({}, {"x": 1})
        ] + [
            mutated(("task_id",), v) for v in ("ok-1", "has space", "", "a/b")
        ]
        for doc in cases:
            schema_ok = self.errors(uri, doc) == []
            try:
                config = RoundConfig.from_request(doc)
            except InvalidRoundRequestError:
                continue  # stricter than the schema is acceptable
            self.assertTrue(schema_ok, f"RoundConfig accepted a request the schema rejects: {str(doc)[:200]}")
            self.assertEqual(self.errors(red_uri, config.to_red_input()), [])

    def test_test_request_and_stored_config_are_valid_round_requests(self):
        uri = "autosoc://contracts/round_request/0.1.0"
        self.assertEqual(self.errors(uri, REQUEST), [])
        config = RoundConfig.from_request(request(permitted_evidence_refs=[{"evidence_id": "e1", "evidence_type": "telemetry"}]))
        self.assertEqual(self.errors(uri, config.to_dict()), [])

    def test_red_input_derived_from_a_round_is_valid(self):
        uri = "autosoc://red_role/interfaces/inputs/red_input/0.1.0"
        example = self.example("valid_round_request.json")
        self.assertEqual(self.errors(uri, RoundConfig.from_request(example).to_red_input()), [])
        self.assertEqual(self.errors(uri, RoundConfig.from_request(REQUEST).to_red_input()), [])

    def test_every_error_the_orchestrator_stores_is_a_valid_error_response(self):
        uri = "autosoc://contracts/error_response/0.1.0"
        clock = FakeClock()
        stored = []

        mgr = make_manager(clock=clock)
        rid = open_round(mgr)
        stored.append(mgr.fail(rid, "dependency", "splunk unavailable", retryable=True, details={"d": 1}).error)

        mgr = make_manager(clock=clock)
        rid = open_round(mgr)
        stored.append(mgr.mark_inconclusive(rid, "no labels", details={"missing": ["labels"]}).error)

        mgr = make_manager(clock=clock)
        rid = open_round(mgr, limits={"max_attempts_per_step": 1})
        mgr.begin_attempt(rid)
        stored.append(mgr.finish_attempt(rid, "failed", error="down", error_category="dependency").error)

        mgr = make_manager(clock=clock)
        rid = open_round(mgr, limits={"step_timeout_seconds": 5})
        clock.tick(6)
        mgr.enforce_timeout(rid)
        stored.append(mgr.get_round(rid).error)

        for error in stored:
            self.assertEqual(self.errors(uri, error), [], error)

    def test_exception_error_responses_are_valid(self):
        uri = "autosoc://contracts/error_response/0.1.0"
        with self.assertRaises(InvalidRoundRequestError) as ctx:
            RoundConfig.from_request({k: v for k, v in REQUEST.items() if k != "criteria"})
        for exc in (ctx.exception, RoundTimedOutError("late"), MissingArtifactError("none"), RetryExhaustedError("x", {"a": 1}, "dependency"), StoreUnavailableError("down", {"error_type": "AutoReconnect"})):
            self.assertEqual(self.errors(uri, exc.to_error_response("task-001", timestamp="2026-11-17T12:00:00+00:00")), [])


if __name__ == "__main__":
    unittest.main()
