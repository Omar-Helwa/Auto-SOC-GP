"""Run one mock Architecture 1 round end-to-end into MongoDB.

Uses the real red_proposal / error_response schemas for validation and mock
services (loaded from the contract example files) for every role. Demonstrates
that the controller connects to the DB and relays data between services.

    python -m shared_services.scripts.demo_round
"""

from __future__ import annotations

import json
from pathlib import Path

from ..config import DB_NAME
from ..controller.round_controller import RoundController
from ..controller.services import ServiceRegistry, static_service
from ..datastore.repository import MongoRepository
from ..datastore.schema_registry import REPO_ROOT

RED_EXAMPLES = REPO_ROOT / "00_shared_contracts" / "red_proposal" / "examples"


def _load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def main() -> int:
    repo = MongoRepository()
    repo.ping()
    repo.ensure_setup()

    task_id = "demo-round-0001"
    red_proposal = _load(RED_EXAMPLES / "valid_red_proposal.json")
    red_proposal["task_id"] = task_id  # thread the round id through

    registry = ServiceRegistry()
    registry.register("red", static_service("red_proposal", lambda _p: red_proposal))
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
        "detection": {"detection_id": "win-encoded-powershell", "rule_version": "3.2.0",
                      "logic_summary": "Alerts on powershell -EncodedCommand."},
        "benign_constraints": {
            "allowed_scenario_families": ["admin_automation"],
            "max_workflow_steps": 5,
            "allowed_actions": ["scheduled_task", "script_execution"],
        },
        "prompt_version": "red-system@0.1.0",
    }

    controller = RoundController(repo, registry)
    outcome = controller.run_round(round_request)

    print(f"Database: {DB_NAME}")
    print(f"Round {outcome.task_id}: {outcome.outcome} ({outcome.reason or 'all steps ran'})")
    print("Stored this round:")
    for role, contract in outcome.stored.items():
        print(f"  - {role:18} -> {contract}")
    print(f"  - feedback_record    -> id {outcome.feedback_id}")
    print("\nDocument counts for this task_id:")
    for contract in ("round_request", "red_proposal", "telemetry_evidence",
                     "blue_proposal", "candidate_rule", "judge_result", "feedback_record"):
        print(f"  {contract:20} {repo.count(contract, {'task_id': task_id})}")
    repo.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
