"""Audit event model and persistence adapter tests."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace

from audit_records import (
    AuditRecord,
    AuditRecordError,
    AuditRecordWriter,
    InMemoryAuditRecordStore,
    MongoAuditRecordStore,
)
from interfaces import InMemoryArtifactStore
from interfaces.inputs import OrchestratorInputAdapter
from interfaces.outputs import OrchestratorOutputAdapter
from round_management import InMemoryRoundStore, RoundManager
from workflow import RoundWorkflow, WorkflowServiceError, WorkflowStepOutput


class PassthroughValidator:
    def validate(self, _contract, message):
        return json.loads(json.dumps(message, allow_nan=False))


class FakeCollection:
    def __init__(self):
        self.rows = []

    def find(self, query, _projection):
        return [row for row in self.rows if row["round_id"] == query["round_id"]]


class FakeRepository:
    def __init__(self):
        self.collection = FakeCollection()

    def save(self, contract, document):
        if contract != "audit_record":
            raise AssertionError(contract)
        self.collection.rows.append(dict(document))
        return document["audit_id"]

    def collection_for(self, contract):
        if contract != "audit_record":
            raise AssertionError(contract)
        return self.collection


class AuditRecordTests(unittest.TestCase):
    def test_writer_persists_ordered_events_with_round_and_task_ids(self):
        store = InMemoryAuditRecordStore()
        times = iter((
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        ))
        writer = AuditRecordWriter(store, clock=lambda: next(times))

        first = writer.record("round_opened", "round-1", input_payload={"seed": 4})
        second = writer.record("component_call_started", "round-1", component="red_role", attempt=1)

        rows = store.list_for_round("round-1")
        self.assertEqual([row["event_type"] for row in rows], ["round_opened", "component_call_started"])
        self.assertEqual(rows[0]["task_id"], "round-1")
        self.assertEqual(rows[0]["round_id"], "round-1")
        self.assertTrue(first.startswith("memory://audit_record/"))
        self.assertTrue(second.startswith("memory://audit_record/"))

    def test_record_rejects_non_json_payloads(self):
        record = AuditRecord(
            task_id="round-1", event_type="round_opened",
            occurred_at="2026-01-01T00:00:00+00:00", input_payload={"value": float("nan")},
        )
        with self.assertRaises(AuditRecordError):
            record.to_document()

    def test_mongo_store_uses_shared_repository_audit_record_mapping(self):
        repository = FakeRepository()
        store = MongoAuditRecordStore(repository)
        writer = AuditRecordWriter(store)

        reference = writer.record("component_call_completed", "round-2", component="platform")

        self.assertTrue(reference.startswith("mongo://audit_record/"))
        self.assertEqual(store.list_for_round("round-2")[0]["component"], "platform")

    def test_workflow_records_round_component_failure_and_close(self):
        root = Path(__file__).resolve().parents[2]
        contracts = root.parent / "00_shared_contracts"
        request = json.loads(
            (contracts / "round_request/examples/valid_round_request.json").read_text(encoding="utf-8")
        )
        manager = RoundManager(InMemoryRoundStore())
        artifacts = InMemoryArtifactStore()
        validator = PassthroughValidator()
        inputs = OrchestratorInputAdapter(manager, artifacts, validator)
        outputs = OrchestratorOutputAdapter(manager, artifacts, validator)
        audit_store = InMemoryAuditRecordStore()
        services = SimpleNamespace(red=SimpleNamespace(run=lambda _payload: WorkflowStepOutput(
            messages={"red_proposal": {"task_id": "wrong-round", "contract_version": "0.1.0"}},
            raw_output="original model response",
            model_id="test-model-v3",
        )))

        result = RoundWorkflow(
            inputs, outputs, services, audit_writer=AuditRecordWriter(audit_store)
        ).run_round(request)

        self.assertEqual(result.state, "failed")
        events = audit_store.list_for_round(request["task_id"])
        self.assertEqual(
            [event["event_type"] for event in events],
            [
                "round_opened", "outbound_input_prepared", "component_call_started",
                "component_output_rejected", "component_call_failed", "round_closed",
            ],
        )
        self.assertEqual(events[1]["input_contract"], "red_input")
        self.assertIn("red_input", events[1]["output_artifact_refs"])
        self.assertEqual(events[2]["component"], "red_role")
        self.assertEqual(events[2]["input_payload"]["task_id"], request["task_id"])
        self.assertIn("round_request", events[2]["input_artifact_refs"])
        self.assertIn("red_input", events[2]["input_artifact_refs"])
        self.assertEqual(events[2]["based_on_transition_sequence"], 1)
        self.assertEqual(events[3]["validation"]["status"], "rejected")
        self.assertEqual(events[3]["raw_output"], "original model response")
        self.assertEqual(events[3]["model_id"], "test-model-v3")
        self.assertEqual(events[3]["transition_sequence"], 2)
        self.assertEqual(events[4]["output_contract_versions"]["red_proposal"], "0.1.0")
        self.assertEqual(events[5]["transition_sequence"], 2)

    def test_workflow_audits_the_saved_error_response_reference(self):
        root = Path(__file__).resolve().parents[2]
        contracts = root.parent / "00_shared_contracts"
        request = json.loads(
            (contracts / "round_request/examples/valid_round_request.json").read_text(encoding="utf-8")
        )
        manager = RoundManager(InMemoryRoundStore())
        artifacts = InMemoryArtifactStore()
        validator = PassthroughValidator()
        inputs = OrchestratorInputAdapter(manager, artifacts, validator)
        outputs = OrchestratorOutputAdapter(manager, artifacts, validator)
        audit_store = InMemoryAuditRecordStore()

        def fail_red(_payload):
            raise WorkflowServiceError("role unavailable", category="dependency")

        services = SimpleNamespace(red=SimpleNamespace(run=fail_red))
        result = RoundWorkflow(
            inputs, outputs, services, audit_writer=AuditRecordWriter(audit_store)
        ).run_round(request)

        events = audit_store.list_for_round(request["task_id"])
        error_event = next(event for event in events if event["event_type"] == "error_response_persisted")
        reference = error_event["output_artifact_refs"]["error_response"]
        stored_error = artifacts.load("error_response", reference)

        self.assertEqual(result.state, "failed")
        self.assertEqual(error_event["validation"]["status"], "accepted")
        self.assertEqual(stored_error["category"], "dependency")
        self.assertEqual(error_event["based_on_transition_sequence"], 1)


if __name__ == "__main__":
    unittest.main()
