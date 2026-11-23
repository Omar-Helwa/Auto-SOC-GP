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

    shared = REPO_ROOT / "00_shared_contracts"
    round_request = _load(shared / "round_request" / "examples" / "valid_round_request.json")
    round_request["task_id"] = task_id

    registry = ServiceRegistry()
    registry.register("red", static_service("red_proposal", lambda _p: red_proposal))
    telemetry = {
        "contract_version": "0.1.0",
        "evidence_id": f"evidence-{task_id}",
        "task_id": task_id,
        "detection_id": round_request["detection"]["detection_id"],
        "evidence_type": "telemetry",
        "evidence_ref": f"evidence://{task_id}/telemetry",
        "verified": True,
    }
    registry.register("platform_execute", static_service("telemetry_evidence", lambda _p: telemetry))
    labels = _load(shared / "telemetry_evidence" / "examples" / "valid_reviewed_label_set.json")
    registry.register("platform_labels", static_service("reviewed_label_set", lambda _p: labels))
    baseline = _load(shared / "candidate_rule" / "examples" / "valid_match_set.json")
    baseline.update(task_id=task_id, role="baseline", rule_version=round_request["detection"]["rule_version"])
    baseline.pop("candidate_ref", None)
    registry.register("platform_baseline", static_service("match_set", lambda _p: baseline))

    blue_proposal = _load(shared / "blue_proposal" / "examples" / "valid_blue_proposal.json")
    blue_proposal["task_id"] = task_id
    candidate_rule = _load(shared / "candidate_rule" / "examples" / "valid_candidate_rule.json")
    candidate_rule["task_id"] = task_id
    candidate_matches = _load(shared / "candidate_rule" / "examples" / "valid_match_set.json")
    candidate_matches.update(
        task_id=task_id,
        candidate_ref=candidate_rule["candidate_id"],
        rule_version=candidate_rule["candidate_rule_version"],
    )
    registry.register("blue", static_service("blue_proposal", lambda _p: blue_proposal))
    registry.register("platform_compile", static_service("candidate_rule", lambda _p: candidate_rule))
    registry.register("platform_candidate_matches", static_service("match_set", lambda _p: candidate_matches))
    judge_result = _load(shared / "judge_result" / "examples" / "valid_judge_result_pass.json")
    judge_result["task_id"] = task_id
    registry.register("judge", static_service("judge_result", lambda _p: judge_result))

    controller = RoundController(repo, registry)
    outcome = controller.run_round(round_request)

    print(f"Database: {DB_NAME}")
    print(f"Round {outcome.task_id}: {outcome.outcome} ({outcome.reason or 'all steps ran'})")
    print("Stored this round:")
    for role, contract in outcome.stored.items():
        print(f"  - {role:18} -> {contract}")
    print(f"  - feedback_record    -> id {outcome.feedback_id}")
    print("\nDocument counts for this task_id:")
    for contract in ("round_request", "red_proposal", "telemetry_evidence", "reviewed_label_set",
                     "blue_proposal", "candidate_rule", "match_set", "judge_result", "feedback_record"):
        print(f"  {contract:20} {repo.count(contract, {'task_id': task_id})}")
    repo.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
