"""Run an Orchestrator mock round into the configured MongoDB backend.

The development Judge is configured for INCONCLUSIVE. This demonstrates
contract persistence and the canonical workflow without claiming an evaluation.

    python -m shared_services.scripts.demo_round
"""

from __future__ import annotations

import json
import sys
from importlib import import_module
from uuid import uuid4

from ..config import DB_NAME
from ..controller.round_controller import RoundController
from ..datastore.repository import MongoRepository
from ..datastore.schema_registry import REPO_ROOT

ORCHESTRATOR_ROOT = REPO_ROOT / "01_orchestrator"
if str(ORCHESTRATOR_ROOT) not in sys.path:
    sys.path.append(str(ORCHESTRATOR_ROOT))

MockWorkflowServices = import_module("dev.mocks").MockWorkflowServices


def main() -> int:
    repo = MongoRepository()
    repo.ping()
    repo.ensure_setup()

    task_id = f"demo-round-{uuid4().hex}"
    request_path = (
        REPO_ROOT / "00_shared_contracts" / "round_request" / "examples"
        / "valid_round_request.json"
    )
    round_request = json.loads(request_path.read_text(encoding="utf-8"))
    round_request["task_id"] = task_id

    outcome = RoundController(repo, MockWorkflowServices("inconclusive")).run_round(
        round_request
    )
    print(f"Backend: {repo.backend}")
    if repo.backend == "mongomock":
        print("WARNING: this round is stored only in process-local memory.")
    print(f"Database: {DB_NAME}")
    print(f"Round {task_id}: {outcome.state}")
    print("Stored artifacts:")
    for artifact, reference in sorted(outcome.record.artifacts.items()):
        print(f"  - {artifact:24} -> {reference}")
    print("Development mocks were used; no acceptance verdict was produced.")
    repo.close()
    return 0 if outcome.state in {"completed", "inconclusive"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
