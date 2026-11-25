"""Run real Red with Orchestrator-owned development services and MongoDB.

Platform, Blue, and Judge use Orchestrator mocks; the Judge is configured to
return INCONCLUSIVE so this smoke run cannot be mistaken for an evaluation.

Run from the repository root with:

    python 99_integration/assembled_runs/run_with_real_red.py
"""

from __future__ import annotations

import importlib.util
import json
import sys
from importlib import import_module
from pathlib import Path
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parents[2]
ORCHESTRATOR_ROOT = REPO_ROOT / "01_orchestrator"
for path in (REPO_ROOT, ORCHESTRATOR_ROOT):
    if str(path) not in sys.path:
        sys.path.append(str(path))

from shared_services.controller.round_controller import RoundController  # noqa: E402
from shared_services.controller.services import WorkflowComponentAdapter  # noqa: E402
from shared_services.datastore.repository import MongoRepository  # noqa: E402

MockWorkflowServices = import_module("dev.mocks").MockWorkflowServices

_spec = importlib.util.spec_from_file_location(
    "red_service_adapter", REPO_ROOT / "99_integration" / "adapters" / "red_service.py"
)
if _spec is None or _spec.loader is None:
    raise ImportError("Unable to load the Red service adapter")
_red_service_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_red_service_mod)


def main() -> int:
    repo = MongoRepository()
    repo.ping()
    repo.ensure_setup()

    task_id = f"assembled-real-red-{uuid4().hex}"
    contracts = REPO_ROOT / "00_shared_contracts"
    round_request = json.loads(
        (contracts / "round_request" / "examples" / "valid_round_request.json").read_text(
            encoding="utf-8"
        )
    )
    round_request["task_id"] = task_id

    services = MockWorkflowServices("inconclusive")
    services.red = WorkflowComponentAdapter(
        _red_service_mod.build_red_service(), "red_proposal"
    )
    outcome = RoundController(repo, services).run_round(round_request)
    print(f"Round {task_id}: {outcome.state}")
    for artifact, reference in sorted(outcome.record.artifacts.items()):
        print(f"  - {artifact:24} -> {reference}")
    if repo.backend == "mongomock":
        print("WARNING: this run is stored only in process-local memory.")
    print("Mock Platform/Blue/Judge services were used; no acceptance verdict was produced.")
    repo.close()
    return 0 if outcome.state in {"completed", "inconclusive"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
