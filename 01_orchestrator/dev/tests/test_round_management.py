"""Run from the 01_orchestrator folder:  python -m unittest discover -s dev/tests -v"""

import copy
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from round_management import (  
    ConcurrencyError,
    InMemoryRoundStore,
    IntegrityError,
    InvalidArgumentError,
    InvalidRoundRequestError,
    InvalidTransitionError,
    JsonFileRoundStore,
    RoundConfig,
    RoundClosedError,
    RoundManager,
    RoundNotFoundError,
    RoundState,
    RoundTimedOutError,
)

REQUEST = {
    "task_id": "task-001",
    "detection": {"name": "suspicious_powershell", "spl": "index=win EventCode=4688"},
    "dataset_ref": "dataset://lab/v1",
    "criteria": {"min_fp_reduction": 0.2, "max_attack_loss": 0},
    "versions": {
        "prompt": "p1", "model": "m1", "rule": "r1",
        "dataset": "d1", "criteria": "c1", "contracts": "v1",
    },
}


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
        id_factory=lambda: f"round-{next(counter):03d}",
    )


def run_to_judged(mgr, rid):
    for state in (
        RoundState.RED_PROPOSED,
        RoundState.TELEMETRY_COLLECTED,
        RoundState.EVIDENCE_VERIFIED,
        RoundState.BLUE_PROPOSED,
        RoundState.CANDIDATE_EXECUTED,
        RoundState.JUDGED,
    ):
        mgr.advance(rid, state, artifact_name=state.value, artifact_ref=f"ref://{state.value}")


class CreateRoundTests(unittest.TestCase):
    def test_create_freezes_config(self):
        mgr = make_manager()
        req = copy.deepcopy(REQUEST)
        rec = mgr.create_round(req)
        req["detection"]["name"] = "tampered"  # caller mutation must not leak in
        self.assertEqual(rec.state, RoundState.CREATED)
        self.assertEqual(rec.round_id, "round-001")
        self.assertEqual(mgr.get_round(rec.round_id).config.detection["name"], "suspicious_powershell")
        mgr.verify_integrity(rec.round_id)

    def test_nested_config_values_are_immutable(self):
        request = copy.deepcopy(REQUEST)
        request["detection"]["nested"] = {"labels": ["a", "b"]}
        config = RoundConfig.from_request(request)
        with self.assertRaises(TypeError):
            config.detection["nested"]["new"] = "value"
        with self.assertRaises(AttributeError):
            config.detection["nested"]["labels"].append("c")
        self.assertEqual(config.to_dict()["detection"]["nested"]["labels"], ["a", "b"])
        reused = RoundConfig(
            task_id=config.task_id,
            detection=config.detection,
            dataset_ref=config.dataset_ref,
            criteria=config.criteria,
            versions=config.versions,
        )
        self.assertEqual(reused.fingerprint(), config.fingerprint())

    def test_strict_json_and_integer_validation(self):
        with self.assertRaises(InvalidRoundRequestError):
            RoundConfig.from_request({**REQUEST, "detection": {"score": float("nan")}})
        with self.assertRaises(InvalidRoundRequestError):
            RoundConfig.from_request({**REQUEST, "max_attempts_per_step": True})

    def test_invalid_requests_rejected(self):
        mgr = make_manager()
        bad = copy.deepcopy(REQUEST)
        del bad["versions"]["model"]
        with self.assertRaises(InvalidRoundRequestError):
            mgr.create_round(bad)
        with self.assertRaises(InvalidRoundRequestError):
            mgr.create_round({**REQUEST, "extra_field": 1})
        with self.assertRaises(InvalidRoundRequestError):
            mgr.create_round({k: v for k, v in REQUEST.items() if k != "criteria"})
        with self.assertRaises(InvalidRoundRequestError):
            mgr.create_round({**REQUEST, "max_attempts_per_step": 0})

    def test_same_request_same_fingerprint(self):
        a = make_manager().create_round(REQUEST)
        b = make_manager().create_round(copy.deepcopy(REQUEST))
        self.assertEqual(a.config_fingerprint, b.config_fingerprint)


class WorkflowTests(unittest.TestCase):
    def test_full_happy_path(self):
        mgr = make_manager()
        rid = mgr.create_round(REQUEST).round_id
        run_to_judged(mgr, rid)
        rec = mgr.complete(rid, "pass", "feedback://rec-1")
        self.assertEqual(rec.state, RoundState.COMPLETED)
        self.assertEqual(rec.outcome, "pass")
        self.assertIsNotNone(rec.closed_at)
        self.assertEqual([t.sequence for t in rec.transitions], list(range(1, 9)))
        self.assertEqual(rec.artifacts["feedback_record"], "feedback://rec-1")
        mgr.verify_integrity(rid)

    def test_reject_still_completes(self):
        mgr = make_manager()
        rid = mgr.create_round(REQUEST).round_id
        run_to_judged(mgr, rid)
        self.assertEqual(mgr.complete(rid, "reject", "feedback://x").outcome, "reject")

    def test_judge_inconclusive_closes_inconclusive(self):
        mgr = make_manager()
        rid = mgr.create_round(REQUEST).round_id
        run_to_judged(mgr, rid)
        rec = mgr.complete(rid, "inconclusive", "feedback://x")
        self.assertEqual(rec.state, RoundState.INCONCLUSIVE)
        self.assertIsNotNone(mgr.error_response(rid))

    def test_cannot_skip_or_reorder(self):
        mgr = make_manager()
        rid = mgr.create_round(REQUEST).round_id
        with self.assertRaises(InvalidTransitionError):
            mgr.advance(rid, RoundState.BLUE_PROPOSED)
        mgr.advance(rid, RoundState.RED_PROPOSED)
        with self.assertRaises(InvalidTransitionError):
            mgr.advance(rid, RoundState.CREATED)

    def test_terminal_exits_need_dedicated_methods(self):
        mgr = make_manager()
        rid = mgr.create_round(REQUEST).round_id
        for target in (RoundState.FAILED, RoundState.INCONCLUSIVE, RoundState.COMPLETED):
            with self.assertRaises(InvalidTransitionError):
                mgr.advance(rid, target)

    def test_complete_only_from_judged(self):
        mgr = make_manager()
        rid = mgr.create_round(REQUEST).round_id
        with self.assertRaises(InvalidTransitionError):
            mgr.complete(rid, "pass", "feedback://x")

    def test_complete_rejects_bad_input(self):
        mgr = make_manager()
        rid = mgr.create_round(REQUEST).round_id
        run_to_judged(mgr, rid)
        with self.assertRaises(InvalidArgumentError):
            mgr.complete(rid, "maybe", "feedback://x")
        with self.assertRaises(InvalidArgumentError):
            mgr.complete(rid, "pass", "")

    def test_unknown_round(self):
        with self.assertRaises(RoundNotFoundError):
            make_manager().get_round("nope")


class FailureTests(unittest.TestCase):
    def test_fail_stores_error_and_closes(self):
        mgr = make_manager()
        rid = mgr.create_round(REQUEST).round_id
        mgr.advance(rid, RoundState.RED_PROPOSED)
        rec = mgr.fail(rid, "dependency", "splunk unavailable", retryable=True)
        self.assertEqual(rec.state, RoundState.FAILED)
        self.assertEqual(rec.error["error_category"], "dependency")
        self.assertEqual(rec.error["failed_in_state"], "red_proposed")
        self.assertTrue(rec.error["retryable"])
        self.assertEqual(mgr.error_response(rid)["message"], "splunk unavailable")

    def test_closed_round_is_immutable(self):
        mgr = make_manager()
        rid = mgr.create_round(REQUEST).round_id
        mgr.fail(rid, "validation", "malformed red output")
        with self.assertRaises(RoundClosedError):
            mgr.advance(rid, RoundState.RED_PROPOSED)
        with self.assertRaises(RoundClosedError):
            mgr.fail(rid, "validation", "again")

    def test_inconclusive_for_missing_evidence(self):
        mgr2 = make_manager()
        rid2 = mgr2.create_round(REQUEST).round_id
        mgr2.advance(rid2, RoundState.RED_PROPOSED)
        mgr2.advance(rid2, RoundState.TELEMETRY_COLLECTED)
        out = mgr2.mark_inconclusive(rid2, "no reviewed labels", details={"missing": ["labels"]})
        self.assertEqual(out.state, RoundState.INCONCLUSIVE)
        self.assertEqual(out.outcome, "inconclusive")
        self.assertEqual(out.error["details"]["missing"], ["labels"])

    def test_unknown_error_category(self):
        mgr = make_manager()
        rid = mgr.create_round(REQUEST).round_id
        with self.assertRaises(InvalidArgumentError):
            mgr.fail(rid, "bogus", "x")


class RetryTimeoutTests(unittest.TestCase):
    def test_retries_bounded_and_fail_round(self):
        mgr = make_manager()
        rid = mgr.create_round({**REQUEST, "max_attempts_per_step": 2}).round_id
        self.assertEqual(mgr.begin_attempt(rid), 1)
        first = mgr.finish_attempt(rid, "failed", error="temporary dependency failure", raw_output_ref="audit://attempt/1")
        self.assertEqual(first.state, RoundState.CREATED)
        self.assertEqual(mgr.begin_attempt(rid), 2)
        rec = mgr.finish_attempt(rid, "failed", error="second failure", raw_output_ref="audit://attempt/2")
        self.assertEqual(rec.state, RoundState.FAILED)
        self.assertEqual(rec.error["error_category"], "retry")
        self.assertEqual([a.outcome for a in rec.attempt_log], ["failed", "failed"])
        self.assertEqual(rec.attempt_log[0].raw_output_ref, "audit://attempt/1")
        mgr.verify_integrity(rid)
        with self.assertRaises(RoundClosedError):
            mgr.begin_attempt(rid)

    def test_attempts_reset_on_new_step(self):
        mgr = make_manager()
        rid = mgr.create_round({**REQUEST, "max_attempts_per_step": 1}).round_id
        mgr.begin_attempt(rid)
        mgr.finish_attempt(rid, "succeeded", raw_output_ref="audit://red")
        mgr.advance(rid, RoundState.RED_PROPOSED)
        self.assertEqual(mgr.begin_attempt(rid), 1)

    def test_timeout(self):
        clock = FakeClock()
        mgr = make_manager(clock=clock)
        rid = mgr.create_round({**REQUEST, "step_timeout_seconds": 60}).round_id
        clock.tick(30)
        self.assertFalse(mgr.enforce_timeout(rid))
        clock.tick(31)
        self.assertTrue(mgr.is_timed_out(rid))
        self.assertTrue(mgr.enforce_timeout(rid))
        rec = mgr.get_round(rid)
        self.assertEqual(rec.state, RoundState.FAILED)
        self.assertEqual(rec.error["error_category"], "timeout")

    def test_timeout_clock_resets_on_advance(self):
        clock = FakeClock()
        mgr = make_manager(clock=clock)
        rid = mgr.create_round({**REQUEST, "step_timeout_seconds": 60}).round_id
        clock.tick(50)
        mgr.advance(rid, RoundState.RED_PROPOSED)
        clock.tick(50)
        self.assertFalse(mgr.is_timed_out(rid))

    def test_late_advance_fails_round_and_closed_timeout_poll_is_safe(self):
        clock = FakeClock()
        mgr = make_manager(clock=clock)
        rid = mgr.create_round({**REQUEST, "step_timeout_seconds": 10}).round_id
        clock.tick(10)
        with self.assertRaises(RoundTimedOutError):
            mgr.advance(rid, RoundState.RED_PROPOSED)
        self.assertEqual(mgr.get_round(rid).state, RoundState.FAILED)
        self.assertFalse(mgr.is_timed_out(rid))
        self.assertFalse(mgr.enforce_timeout(rid))

    def test_attempt_result_rejects_non_json_error_details(self):
        mgr = make_manager()
        rid = mgr.create_round(REQUEST).round_id
        with self.assertRaises(InvalidArgumentError):
            mgr.fail(rid, "internal", "bad details", details={"bad": {1, 2}})

    def test_clock_regression_keeps_history_valid(self):
        clock = FakeClock()
        mgr = make_manager(clock=clock)
        rid = mgr.create_round(REQUEST).round_id
        clock.tick(-5)
        mgr.advance(rid, RoundState.RED_PROPOSED)
        mgr.verify_integrity(rid)


class PersistenceTests(unittest.TestCase):
    def test_json_store_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = make_manager(store=JsonFileRoundStore(tmp))
            rid = mgr.create_round(REQUEST).round_id
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
            mgr2.verify_integrity(rid)
            self.assertEqual(JsonFileRoundStore(tmp).list_ids(), [rid])

    def test_unsafe_id_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(Exception):
                JsonFileRoundStore(tmp).load("../evil")

    def test_corrupt_json_is_integrity_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = JsonFileRoundStore(tmp)
            rid = make_manager(store=store).create_round(REQUEST).round_id
            with open(os.path.join(tmp, f"{rid}.json"), "w", encoding="utf-8") as fh:
                fh.write("{")
            with self.assertRaises(IntegrityError):
                store.load(rid)

    def test_failed_json_serialization_does_not_bump_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = JsonFileRoundStore(tmp)
            rid = make_manager(store=store).create_round(REQUEST).round_id
            rec = store.load(rid)
            old_revision = rec.revision
            rec.error = {"unsupported": {1, 2}}
            with self.assertRaises(IntegrityError):
                store.save(rec)
            self.assertEqual(rec.revision, old_revision)

    def test_stale_write_detected(self):
        store = InMemoryRoundStore()
        mgr = make_manager(store=store)
        rid = mgr.create_round(REQUEST).round_id
        stale = store.load(rid)
        mgr.advance(rid, RoundState.RED_PROPOSED)
        with self.assertRaises(ConcurrencyError):
            store.save(stale)

    def test_json_store_instances_coordinate_writers(self):
        with tempfile.TemporaryDirectory() as tmp:
            store_a = JsonFileRoundStore(tmp)
            store_b = JsonFileRoundStore(tmp)
            mgr = make_manager(store=store_a)
            rid = mgr.create_round(REQUEST).round_id
            stale_a = store_a.load(rid)
            stale_b = store_b.load(rid)
            barrier = threading.Barrier(2)
            results = []

            def save_stale(store, record):
                barrier.wait()
                try:
                    store.save(record)
                    results.append("saved")
                except ConcurrencyError:
                    results.append("stale")

            threads = [
                threading.Thread(target=save_stale, args=(store_a, stale_a)),
                threading.Thread(target=save_stale, args=(store_b, stale_b)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertCountEqual(results, ["saved", "stale"])

    def test_tampered_config_detected(self):
        store = InMemoryRoundStore()
        mgr = make_manager(store=store)
        rid = mgr.create_round(REQUEST).round_id
        rec = store.load(rid)
        rec.config_fingerprint = "0" * 64
        store.save(rec)
        with self.assertRaises(IntegrityError):
            mgr.verify_integrity(rid)

    def test_tampered_outcome_detected(self):
        store = InMemoryRoundStore()
        mgr = make_manager(store=store)
        rid = mgr.create_round(REQUEST).round_id
        rec = store.load(rid)
        rec.outcome = "pass"
        store.save(rec)
        with self.assertRaises(IntegrityError):
            mgr.verify_integrity(rid)

    def test_tampered_artifact_index_detected(self):
        store = InMemoryRoundStore()
        mgr = make_manager(store=store)
        rid = mgr.create_round(REQUEST).round_id
        mgr.advance(rid, RoundState.RED_PROPOSED, artifact_name="proposal", artifact_ref="ref://one")
        rec = store.load(rid)
        rec.artifacts["proposal"] = "ref://tampered"
        store.save(rec)
        with self.assertRaises(IntegrityError):
            mgr.verify_integrity(rid)


if __name__ == "__main__":
    unittest.main()
