"""Run one complete mock-only round against memory or Mongo persistence.

Examples (from 01_orchestrator):
    python -m dev.sandbox.run_mock_round --scenario pass
    python -m dev.sandbox.run_mock_round --scenario partial_persistence_failure --storage mongo
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ORCHESTRATOR_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = ORCHESTRATOR_ROOT.parent
sys.path.insert(0, str(REPO_ROOT))

from dev.mocks import FailOnceArtifactStore, MockWorkflowServices  # noqa: E402
from interfaces import InMemoryArtifactStore, InterfaceValidator  # noqa: E402
from round_management import InMemoryRoundStore  # noqa: E402
from workflow import WorkflowBlockedError, create_mongo_workflow, create_workflow  # noqa: E402


SCENARIOS = (
    "pass", "reject", "inconclusive", "malformed_output",
    "retry_exhaustion", "timeout", "partial_persistence_failure",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=SCENARIOS, default="pass")
    parser.add_argument("--storage", choices=("memory", "mongo"), default="memory")
    parser.add_argument("--mongo-uri", help="Mongo URI; defaults to AUTOSOC_MONGO_URI")
    parser.add_argument("--db-name", help="Mongo database; defaults to AUTOSOC_DB")
    args = parser.parse_args()

    request_path = ORCHESTRATOR_ROOT / "dev" / "fixtures" / "round_requests" / f"{args.scenario}.json"
    request = json.loads(request_path.read_text(encoding="utf-8"))
    services = MockWorkflowServices(args.scenario)
    repository = None
    if args.storage == "mongo":
        from shared_services.config import DB_NAME, MONGO_URI
        from shared_services.datastore.repository import MongoRepository

        repository = MongoRepository(
            uri=args.mongo_uri or MONGO_URI,
            db_name=args.db_name or DB_NAME,
        )
        workflow = create_mongo_workflow(repository, services, validator=InterfaceValidator())
    else:
        workflow = create_workflow(
            InMemoryRoundStore(), InMemoryArtifactStore(), services,
            validator=InterfaceValidator(), allow_non_mongo_stores=True,
        )

    if args.scenario == "partial_persistence_failure":
        fault_store = FailOnceArtifactStore(workflow.artifacts)
        workflow.artifacts = fault_store
        workflow.inputs.artifacts = fault_store
        workflow.outputs.artifacts = fault_store

    try:
        try:
            result = workflow.run_round(request)
        except WorkflowBlockedError as exc:
            result = workflow.run_open_round(exc.round_id)
        print(json.dumps({
            "task_id": result.round_id,
            "state": result.state,
            "outcome": result.record.outcome,
            "error_category": (result.record.error or {}).get("category"),
            "artifact_refs": result.record.artifacts,
            "audit_event_count": len(workflow.audit_writer.store.list_for_round(result.round_id)),
            "storage": args.storage,
        }, indent=2))
        return 0 if result.state in {"completed", "inconclusive", "failed"} else 1
    finally:
        if repository is not None:
            repository.close()


if __name__ == "__main__":
    raise SystemExit(main())
