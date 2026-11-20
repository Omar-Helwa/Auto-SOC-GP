"""Assembled round: REAL Red component + mock other services -> MongoDB.

Demonstrates the end-to-end pipeline the project will run once every component
is ready. Today it uses the real Red component (02_red_role) wired through its
adapter, and mocks for platform/blue/judge. As each teammate finishes, replace
their mock with a real adapter the same way `build_red_service` does.

    # run from the repo root (99_integration is not an importable module name):
    python 99_integration/assembled_runs/run_with_real_red.py
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from shared_services.controller.round_controller import RoundController  # noqa: E402
from shared_services.controller.services import ServiceRegistry, static_service  # noqa: E402
from shared_services.datastore.repository import MongoRepository  # noqa: E402

# Import the adapter by file path (99_integration is not an importable name).
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "red_service_adapter", REPO_ROOT / "99_integration" / "adapters" / "red_service.py"
)
_red_service_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_red_service_mod)
build_red_service = _red_service_mod.build_red_service


def main() -> int:
    repo = MongoRepository()
    repo.ping()
    repo.ensure_setup()

    task_id = "assembled-real-red-0001"

    registry = ServiceRegistry()
    # REAL Red component (mock model gateway inside; swap for hosted model later).
    registry.register("red", build_red_service())
    # Mock stand-ins for the services not finished yet.
    registry.register("platform_execute", static_service(
        "telemetry_evidence", lambda _p: {"task_id": task_id, "evidence": "mock-telemetry"}))
    registry.register("blue", static_service(
        "blue_proposal", lambda _p: {"task_id": task_id, "edit": "mock-rule-edit"}))
    registry.register("platform_compile", static_service(
        "candidate_rule", lambda _p: {"task_id": task_id, "rule": "mock-candidate"}))
    registry.register("judge", static_service(
        "judge_result", lambda _p: {"task_id": task_id, "decision": "pass"}))

    round_request = {
        "task_id": task_id,
        "detection": {
            "detection_id": "win-encoded-powershell",
            "rule_version": "3.2.0",
            "logic_summary": "Alerts on powershell.exe run with -EncodedCommand.",
        },
        "benign_constraints": {
            "allowed_scenario_families": ["admin_automation", "it_maintenance"],
            "max_workflow_steps": 5,
            "allowed_actions": ["scheduled_task", "script_execution", "process_execution"],
        },
        "prompt_version": "red-system@0.1.0",
    }

    outcome = RoundController(repo, registry).run_round(round_request)
    print(f"Round {outcome.task_id}: {outcome.outcome} ({outcome.reason or 'all steps ran'})")
    for role, contract in outcome.stored.items():
        print(f"  - {role:18} -> {contract}")

    # Show the REAL proposal the Red component produced, read back from Mongo.
    proposals = repo.find_by_task("red_proposal", task_id)
    if proposals:
        p = proposals[-1]
        print("\nReal red_proposal stored:")
        print(f"  proposal_id : {p['proposal_id']}")
        print(f"  family      : {p['scenario']['family']}")
        print(f"  steps       : {len(p['scenario']['workflow_steps'])}")
    repo.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
