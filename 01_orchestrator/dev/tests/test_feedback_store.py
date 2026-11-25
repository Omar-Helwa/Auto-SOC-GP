"""Feedback storage reuses contract artifacts and resolves their references."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from feedback_store import FeedbackStore
from interfaces import InMemoryArtifactStore, InterfaceValidator, MongoContractArtifactStore
from interfaces.outputs import OrchestratorOutputAdapter
from round_management import InMemoryRoundStore, RoundManager, RoundState
from workflow import create_workflow
from bson import ObjectId


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT.parent / "00_shared_contracts"


def load_feedback(example: str = "valid_feedback_record.json") -> dict:
    path = CONTRACTS / "feedback_record" / "examples" / example
    return json.loads(path.read_text(encoding="utf-8"))


def valid_artifact_payloads(task_id: str, judge_result: dict) -> dict[str, tuple[str, dict]]:
    def load_example(folder: str, filename: str) -> dict:
        path = CONTRACTS / folder / "examples" / filename
        return json.loads(path.read_text(encoding="utf-8"))

    red = load_example("red_proposal", "valid_red_proposal.json")
    red["task_id"] = task_id
    blue = load_example("blue_proposal", "valid_blue_proposal.json")
    blue["task_id"] = task_id
    candidate_rule = load_example("candidate_rule", "valid_candidate_rule.json")
    candidate_rule["task_id"] = task_id

    telemetry = {
        "contract_version": "0.1.0",
        "evidence_id": f"evidence-{task_id}",
        "task_id": task_id,
        "proposal_id": red["proposal_id"],
        "detection_id": red["detection_under_test"]["detection_id"],
        "source": "splunk",
        "execution": {
            "execution_id": f"execution-{task_id}",
            "status": "succeeded",
            "operation_id": f"operation-{task_id}",
            "approval_id": f"approval-{task_id}",
            "started_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:00:01Z",
            "event_count": 0,
            "truncated": False,
        },
        "events": [],
    }
    telemetry["content_sha256"] = hashlib.sha256(
        json.dumps(
            telemetry,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()

    baseline = load_example("candidate_rule", "valid_match_set.json")
    baseline.update(task_id=task_id, role="baseline")
    baseline.pop("candidate_ref", None)
    candidate = load_example("candidate_rule", "valid_match_set.json")
    candidate["task_id"] = task_id
    candidate_rule["task_id"] = task_id
    judge_result["task_id"] = task_id

    return {
        "red_proposal": ("red_proposal", red),
        "telemetry_evidence": ("telemetry_evidence", telemetry),
        "reviewed_label_set": (
            "reviewed_label_set",
            load_example("telemetry_evidence", "valid_reviewed_label_set.json"),
        ),
        "blue_proposal": ("blue_proposal", blue),
        "candidate_rule": ("candidate_rule", candidate_rule),
        "baseline_match_set": ("match_set", baseline),
        "candidate_match_set": ("match_set", candidate),
        "judge_result": ("judge_result", judge_result),
    }


def store_feedback_and_artifacts(feedback: dict):
    artifacts = InMemoryArtifactStore()
    for artifact_name, (contract, payload) in valid_artifact_payloads(
        feedback["task_id"], copy.deepcopy(feedback["judge_result"])
    ).items():
        feedback["artifact_refs"][artifact_name] = artifacts.save(contract, payload)
    return artifacts


class FakeCollection:
    def __init__(self):
        self.rows = []

    def find(self, query):
        return [row for row in self.rows if row.get("task_id") == query.get("task_id")]


class FakeMongoRepository:
    def __init__(self):
        self.collections = {}

    def collection_for(self, contract):
        return self.collections.setdefault(contract, FakeCollection())

    def save(self, contract, document):
        object_id = ObjectId()
        self.collection_for(contract).rows.append({"_id": object_id, **copy.deepcopy(document)})
        return str(object_id)


class FeedbackStoreTests(unittest.TestCase):
    def setUp(self):
        self.validator = InterfaceValidator()

    def test_save_is_idempotent_and_does_not_create_a_second_feedback_copy(self):
        feedback = load_feedback()
        artifacts = store_feedback_and_artifacts(feedback)
        store = FeedbackStore(artifacts, self.validator)

        first_ref = store.save(feedback)
        retry = copy.deepcopy(feedback)
        retry["recorded_at"] = "2026-11-24T00:00:00Z"
        retry_ref = store.save(retry)

        self.assertEqual(first_ref, retry_ref)
        self.assertEqual(len(artifacts.find_by_task("feedback_record", feedback["task_id"])), 1)

    def test_mongo_artifact_store_queries_the_existing_feedback_collection(self):
        feedback = load_feedback()
        repository = FakeMongoRepository()
        artifacts = MongoContractArtifactStore(repository)
        store = FeedbackStore(artifacts, self.validator)

        reference = store.save(feedback)
        loaded = store.get_by_task(feedback["task_id"])

        self.assertEqual(reference, f"mongo://feedback_record/{repository.collection_for('feedback_record').rows[0]['_id']}")
        self.assertEqual(loaded["task_id"], feedback["task_id"])
        self.assertEqual(len(repository.collection_for("feedback_record").rows), 1)

    def test_get_bundle_resolves_role_artifacts_and_only_pass_is_retrieval_eligible(self):
        feedback = load_feedback()
        artifacts = store_feedback_and_artifacts(feedback)
        store = FeedbackStore(artifacts, self.validator)
        store.save(feedback)

        bundle = store.get_bundle(feedback["task_id"])

        self.assertIsNotNone(bundle)
        self.assertTrue(bundle.retrieval_eligible)
        self.assertIn("red_proposal", bundle.artifact_payloads)
        self.assertIn("baseline_match_set", bundle.artifact_payloads)
        self.assertEqual(bundle.artifact_payloads["judge_result"], feedback["judge_result"])

    def test_inconclusive_feedback_is_not_a_positive_retrieval_example(self):
        feedback = load_feedback("valid_feedback_record_inconclusive.json")
        artifacts = store_feedback_and_artifacts(feedback)
        store = FeedbackStore(artifacts, self.validator)
        store.save(feedback)

        bundle = store.get_bundle(feedback["task_id"])

        self.assertFalse(bundle.retrieval_eligible)

    def test_missing_task_returns_no_feedback(self):
        store = FeedbackStore(InMemoryArtifactStore(), self.validator)
        self.assertIsNone(store.get_by_task("no-such-task"))
        self.assertEqual(store.list_for_task("no-such-task"), [])

    def test_non_mongo_workflow_stores_require_explicit_development_opt_in(self):
        with self.assertRaisesRegex(ValueError, "Non-Mongo workflow stores are disabled"):
            create_workflow(InMemoryRoundStore(), InMemoryArtifactStore(), SimpleNamespace())

        workflow = create_workflow(
            InMemoryRoundStore(), InMemoryArtifactStore(), SimpleNamespace(),
            validator=self.validator, allow_non_mongo_stores=True,
        )
        self.assertIsNotNone(workflow)

    def test_output_adapter_saves_once_then_closes_round_with_retrievable_ref(self):
        request = json.loads(
            (CONTRACTS / "round_request" / "examples" / "valid_round_request.json").read_text(encoding="utf-8")
        )
        round_id = request["task_id"]
        artifacts = InMemoryArtifactStore()
        manager = RoundManager(InMemoryRoundStore())
        manager.create_round(request)

        judge_result = load_feedback()["judge_result"]
        judge_result["task_id"] = round_id
        payloads = valid_artifact_payloads(round_id, judge_result)
        refs = {
            name: artifacts.save(contract, payload)
            for name, (contract, payload) in payloads.items()
            if name != "judge_result"
        }
        refs["judge_result"] = artifacts.save("judge_result", judge_result)

        manager.advance(round_id, RoundState.RED_PROPOSED, artifacts={"red_proposal": refs["red_proposal"]})
        manager.advance(round_id, RoundState.TELEMETRY_COLLECTED)
        manager.advance(
            round_id, RoundState.EVIDENCE_VERIFIED,
            artifacts={name: refs[name] for name in ("telemetry_evidence", "reviewed_label_set", "baseline_match_set")},
        )
        manager.advance(round_id, RoundState.BLUE_PROPOSED, artifacts={"blue_proposal": refs["blue_proposal"]})
        manager.advance(
            round_id, RoundState.CANDIDATE_EXECUTED,
            artifacts={name: refs[name] for name in ("candidate_rule", "candidate_match_set")},
        )
        manager.advance(round_id, RoundState.JUDGED, artifacts={"judge_result": refs["judge_result"]})

        outputs = OrchestratorOutputAdapter(manager, artifacts, self.validator)
        completed = outputs.complete_round(round_id)
        feedback_docs = artifacts.find_by_task("feedback_record", round_id)
        bundle = outputs.feedback_store.get_bundle(round_id)

        self.assertEqual(completed.state.value, "completed")
        self.assertEqual(completed.artifacts["feedback_record"], feedback_docs[0][0])
        self.assertEqual(len(feedback_docs), 1)
        self.assertTrue(bundle.retrieval_eligible)
        self.assertEqual(bundle.artifact_payloads["red_proposal"]["task_id"], round_id)


if __name__ == "__main__":
    unittest.main()
