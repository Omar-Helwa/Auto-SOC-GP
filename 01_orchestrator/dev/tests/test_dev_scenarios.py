"""End-to-end mock scenarios through the real Orchestrator workflow."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ORCHESTRATOR_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = ORCHESTRATOR_ROOT.parent
sys.path.insert(0, str(REPO_ROOT))

from dev.mocks import FailOnceArtifactStore, MockWorkflowServices  # noqa: E402
from interfaces import InMemoryArtifactStore, InterfaceValidator  # noqa: E402
from round_management import InMemoryRoundStore  # noqa: E402
from workflow import WorkflowBlockedError, create_workflow  # noqa: E402


FIXTURES = ORCHESTRATOR_ROOT / "dev" / "fixtures"
SCENARIOS = (
    "pass", "reject", "inconclusive", "malformed_output",
    "retry_exhaustion", "timeout", "partial_persistence_failure",
)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class MockWorkflowScenarioTests(unittest.TestCase):
    def test_fixed_scenario_requests_have_expected_outcome_records(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario):
                request = read_json(FIXTURES / "round_requests" / f"{scenario}.json")
                expected = read_json(FIXTURES / "expected" / f"{scenario}.json")
                self.assertEqual(request["task_id"], f"dev-{scenario.replace('_', '-')}")
                self.assertEqual(expected["scenario"], scenario)

    def test_pass_reject_inconclusive_and_partial_write_recovery(self):
        for scenario in ("pass", "reject", "inconclusive", "partial_persistence_failure"):
            with self.subTest(scenario=scenario):
                result, workflow, services = self._run(scenario)
                expected = read_json(FIXTURES / "expected" / f"{scenario}.json")
                self.assertEqual(result.state, expected["terminal_state"])
                self.assertEqual(result.record.outcome, expected["outcome"])
                actual_attempts: dict[str, list[str]] = {}
                for attempt in result.record.attempt_log:
                    actual_attempts.setdefault(attempt.state.value, []).append(attempt.outcome)
                self.assertEqual(actual_attempts, expected["attempt_outcomes"])
                if "error_category" in expected:
                    self.assertEqual(result.record.error["category"], expected["error_category"])
                self.assertTrue(workflow.audit_writer.store.list_for_round(result.round_id))
                if result.state == "completed":
                    bundle = workflow.outputs.feedback_store.get_bundle(result.round_id)
                    self.assertIsNotNone(bundle)
                    self.assertEqual(bundle.feedback_record["decision"]["status"], result.record.outcome.upper())
                    self.assertEqual(bundle.retrieval_eligible, result.record.outcome == "pass")
                    for ref_name, reference in result.record.artifacts.items():
                        contract = {
                            "baseline_match_set": "match_set",
                            "candidate_match_set": "match_set",
                        }.get(ref_name, ref_name)
                        workflow.artifacts.load(contract, reference)
                if scenario == "partial_persistence_failure":
                    self.assertTrue(workflow.artifacts.failed)
                    self.assertGreaterEqual(services.platform.verify_calls, 2)
                    record = result.record
                    evidence_attempts = [a for a in record.attempt_log if a.state.value == "evidence_verified"]
                    self.assertEqual([a.outcome for a in evidence_attempts], ["failed", "succeeded"])

    def test_malformed_output_fails_validation_and_retry_exhaustion_fails_dependency(self):
        for scenario in ("malformed_output", "retry_exhaustion"):
            with self.subTest(scenario=scenario):
                result, _workflow, services = self._run(scenario)
                expected = read_json(FIXTURES / "expected" / f"{scenario}.json")
                self.assertEqual(result.state, expected["terminal_state"])
                self.assertEqual(result.record.outcome, expected["outcome"])
                actual_attempts: dict[str, list[str]] = {}
                for attempt in result.record.attempt_log:
                    actual_attempts.setdefault(attempt.state.value, []).append(attempt.outcome)
                self.assertEqual(actual_attempts, expected["attempt_outcomes"])
                self.assertEqual(result.record.error["category"], expected["error_category"])
                self.assertEqual(services.red.calls, 2 if scenario == "retry_exhaustion" else 1)

    def test_timeout_is_classified_and_round_is_closed(self):
        result, _workflow, _services = self._run("timeout")
        expected = read_json(FIXTURES / "expected" / "timeout.json")
        self.assertEqual(result.state, expected["terminal_state"])
        self.assertEqual(result.record.outcome, expected["outcome"])
        self.assertEqual(
            {"red_proposed": [attempt.outcome for attempt in result.record.attempt_log]},
            expected["attempt_outcomes"],
        )
        self.assertEqual(result.record.error["category"], expected["error_category"])

    def _run(self, scenario: str):
        request = read_json(FIXTURES / "round_requests" / f"{scenario}.json")
        base_store = InMemoryArtifactStore()
        artifacts = (
            FailOnceArtifactStore(base_store)
            if scenario == "partial_persistence_failure"
            else base_store
        )
        services = MockWorkflowServices(scenario)
        workflow = create_workflow(
            InMemoryRoundStore(), artifacts, services,
            validator=InterfaceValidator(), allow_non_mongo_stores=True,
        )
        try:
            result = workflow.run_round(request)
        except WorkflowBlockedError as exc:
            # The workflow raises only when a non-retryable failure leaves the
            # round open; fetch the durable terminal result for assertions.
            result = workflow.run_open_round(exc.round_id)
        return result, workflow, services


if __name__ == "__main__":
    unittest.main()
