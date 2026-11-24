"""Feedback storage reuses contract artifacts and resolves their references."""

from __future__ import annotations

import copy
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


def store_feedback_and_artifacts(feedback: dict):
    artifacts = InMemoryArtifactStore()
    contract_names = {
        "red_proposal": "red_proposal",
        "telemetry_evidence": "telemetry_evidence",
        "reviewed_label_set": "reviewed_label_set",
        "blue_proposal": "blue_proposal",
        "candidate_rule": "candidate_rule",
        "baseline_match_set": "match_set",
        "candidate_match_set": "match_set",
        "judge_result": "judge_result",
    }
    for artifact_name, contract in contract_names.items():
        if artifact_name == "judge_result":
            payload = feedback["judge_result"]
        else:
            payload = {"task_id": feedback["task_id"], "artifact": artifact_name}
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

        payloads = {
            "red_proposal": ("red_proposal", {"task_id": round_id}),
            "telemetry_evidence": ("telemetry_evidence", {"task_id": round_id}),
            "reviewed_label_set": ("reviewed_label_set", {"task_id": round_id}),
            "baseline_match_set": ("match_set", {"task_id": round_id}),
            "blue_proposal": ("blue_proposal", {"task_id": round_id}),
            "candidate_rule": ("candidate_rule", {"task_id": round_id}),
            "candidate_match_set": ("match_set", {"task_id": round_id}),
        }
        refs = {
            name: artifacts.save(contract, payload)
            for name, (contract, payload) in payloads.items()
        }
        judge_result = load_feedback()["judge_result"]
        judge_result["task_id"] = round_id
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
