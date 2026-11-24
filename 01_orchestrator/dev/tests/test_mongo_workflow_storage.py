"""Live Mongo smoke test for Orchestrator request, Red input, and audit wiring."""

from __future__ import annotations

import json
import os
import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = ROOT.parent
sys.path.insert(0, str(REPO_ROOT))

from shared_services.datastore.repository import MongoRepository  # noqa: E402
from dev.mocks import MockWorkflowServices  # noqa: E402
from workflow import create_mongo_workflow  # noqa: E402

TEST_MONGO_URI = os.environ.get("AUTOSOC_TEST_MONGO_URI", "mongodb://localhost:27017")


def mongo_is_available() -> bool:
    try:
        from pymongo import MongoClient

        client = MongoClient(TEST_MONGO_URI, serverSelectionTimeoutMS=400)
        client.admin.command("ping")
        client.close()
        return True
    except Exception:
        return False


def drop_database(db_name: str) -> None:
    from pymongo import MongoClient

    client = MongoClient(TEST_MONGO_URI, serverSelectionTimeoutMS=1000)
    try:
        client.drop_database(db_name)
    finally:
        client.close()


@unittest.skipUnless(mongo_is_available(), "MongoDB server is unavailable")
class MongoWorkflowStorageTests(unittest.TestCase):
    def test_factory_persists_request_red_input_round_and_audit_in_one_database(self):
        db_name = f"autosoc_test_workflow_{uuid.uuid4().hex[:10]}"
        repository = MongoRepository(uri=TEST_MONGO_URI, db_name=db_name)
        self.addCleanup(repository.close)
        self.addCleanup(repository._client.drop_database, db_name)

        services = SimpleNamespace()
        workflow = create_mongo_workflow(repository, services)
        request_path = REPO_ROOT / "00_shared_contracts" / "round_request" / "examples" / "valid_round_request.json"
        request = json.loads(request_path.read_text(encoding="utf-8"))

        record = workflow.inputs.open_round(request)
        red_input = workflow.outputs.build_red_input(record.round_id)
        events = workflow.audit_writer.store.list_for_round(record.round_id)

        self.assertEqual(repository.db["round_requests"].count_documents({"task_id": record.round_id}), 1)
        self.assertEqual(repository.db["rounds"].count_documents({"_id": record.round_id}), 1)
        self.assertEqual(repository.db["red_inputs"].count_documents({"task_id": record.round_id}), 1)
        self.assertEqual(red_input["task_id"], record.round_id)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "outbound_input_prepared")
        self.assertTrue(events[0]["output_artifact_refs"]["red_input"].startswith("mongo://red_input/"))

    def test_completed_mock_round_and_referenced_artifacts_survive_fresh_workflow(self):
        db_name = f"autosoc_test_durable_{uuid.uuid4().hex[:10]}"
        repository = MongoRepository(uri=TEST_MONGO_URI, db_name=db_name)
        self.addCleanup(repository.close)
        self.addCleanup(drop_database, db_name)
        services = MockWorkflowServices("pass")
        workflow = create_mongo_workflow(repository, services)

        request_path = (
            ROOT / "dev" / "fixtures" / "round_requests" / "pass.json"
        )
        request = json.loads(request_path.read_text(encoding="utf-8"))
        result = workflow.run_round(request)

        self.assertEqual(result.state, "completed")
        self.assertEqual(result.record.outcome, "pass")
        original_revision = result.record.revision
        self.assertTrue(result.record.artifacts["feedback_record"].startswith("mongo://feedback_record/"))
        self.assertTrue(workflow.audit_writer.store.list_for_round(result.round_id))

        # A new repository and composition root must recover the terminal round
        # and load every persisted contract artifact from their exact refs.
        repository.close()
        fresh_repository = MongoRepository(uri=TEST_MONGO_URI, db_name=db_name)
        self.addCleanup(fresh_repository.close)
        fresh_workflow = create_mongo_workflow(fresh_repository, MockWorkflowServices("pass"))
        reloaded = fresh_workflow.run_open_round(result.round_id)

        self.assertEqual(reloaded.state, "completed")
        self.assertEqual(reloaded.record.revision, original_revision)
        for artifact_name, reference in reloaded.record.artifacts.items():
            contract = {"baseline_match_set": "match_set", "candidate_match_set": "match_set"}.get(
                artifact_name, artifact_name
            )
            payload = fresh_workflow.artifacts.load(contract, reference)
            if "task_id" in payload:
                self.assertEqual(payload["task_id"], result.round_id)
        feedback = fresh_workflow.outputs.feedback_store.get_bundle(result.round_id)
        self.assertIsNotNone(feedback)
        self.assertTrue(feedback.retrieval_eligible)
        audit = fresh_workflow.audit_writer.store.list_for_round(result.round_id)
        self.assertTrue(any(event["event_type"] == "component_call_completed" for event in audit))


if __name__ == "__main__":
    unittest.main()
