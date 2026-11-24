"""Run one mock Architecture 1 round end-to-end into MongoDB.

Uses contract examples and mock services for every role. Demonstrates that the
controller relays and persists a complete round.

    python -m shared_services.scripts.demo_round
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..config import DB_NAME
from ..controller.round_controller import RoundController
from ..controller.services import ServiceRegistry, static_service
from ..datastore.repository import MongoRepository
from ..datastore.schema_registry import REPO_ROOT

SHARED = REPO_ROOT / "00_shared_contracts"


def _load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {key: value for key, value in data.items() if not key.startswith("_")}


def _telemetry_evidence(task_id: str, proposal_id: str, detection_id: str) -> dict:
    telemetry = {
        "contract_version": "0.1.0",
        "evidence_id": f"evidence-{task_id}",
        "task_id": task_id,
        "proposal_id": proposal_id,
        "detection_id": detection_id,
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
    return telemetry


def main() -> int:
    repo = MongoRepository()
    repo.ping()
    repo.ensure_setup()

    task_id = "demo-round-0001"
    round_request = _load(
        SHARED / "round_request" / "examples" / "valid_round_request.json"
    )
    round_request["task_id"] = task_id

    red_proposal = _load(
        SHARED / "red_proposal" / "examples" / "valid_red_proposal.json"
    )
    red_proposal["task_id"] = task_id

    blue_proposal = _load(
        SHARED / "blue_proposal" / "examples" / "valid_blue_proposal.json"
    )
    blue_proposal["task_id"] = task_id

    detection = round_request["detection"]
    dataset = round_request["dataset"]
    candidate_rule = _load(
        SHARED / "candidate_rule" / "examples" / "valid_candidate_rule.json"
    )
    candidate_rule.update(
        task_id=task_id,
        proposal_id=blue_proposal["proposal_id"],
        detection_id=detection["detection_id"],
    )

    telemetry = _telemetry_evidence(
        task_id,
        red_proposal["proposal_id"],
        red_proposal["detection_under_test"]["detection_id"],
    )
    labels = _load(
        SHARED / "telemetry_evidence" / "examples" / "valid_reviewed_label_set.json"
    )

    baseline = _load(
        SHARED / "candidate_rule" / "examples" / "valid_match_set.json"
    )
    baseline.update(
        match_set_id=f"ms-baseline-{task_id}",
        task_id=task_id,
        role="baseline",
        detection_id=detection["detection_id"],
        rule_version=detection["rule_version"],
    )
    baseline["dataset"].update(dataset)
    baseline["execution"]["execution_id"] = f"exec-baseline-{task_id}"
    baseline.pop("candidate_ref", None)

    candidate_matches = _load(
        SHARED / "candidate_rule" / "examples" / "valid_match_set.json"
    )
    candidate_matches.update(
        match_set_id=f"ms-candidate-{task_id}",
        task_id=task_id,
        role="candidate",
        detection_id=detection["detection_id"],
        rule_version=candidate_rule["candidate_rule_version"],
        candidate_ref=candidate_rule["candidate_id"],
    )
    candidate_matches["dataset"].update(dataset)
    candidate_matches["execution"]["execution_id"] = f"exec-candidate-{task_id}"

    judge_result = _load(
        SHARED / "judge_result" / "examples" / "valid_judge_result_pass.json"
    )
    judge_result["task_id"] = task_id
    judge_result["evaluation_summary"].update(
        detection_id=detection["detection_id"],
        dataset_id=dataset["dataset_id"],
        dataset_version=dataset["dataset_version"],
        evaluation_set_id=dataset["evaluation_set_id"],
        total_events=labels["coverage"]["total_events"],
        baseline_rule_version=detection["rule_version"],
        candidate_rule_version=candidate_rule["candidate_rule_version"],
    )
    judge_result["provenance"].update(
        baseline_match_set_id=baseline["match_set_id"],
        candidate_match_set_id=candidate_matches["match_set_id"],
        baseline_execution_id=baseline["execution"]["execution_id"],
        candidate_execution_id=candidate_matches["execution"]["execution_id"],
        candidate_ref=candidate_rule["candidate_id"],
        label_set_id=labels["label_set_id"],
        label_set_version=labels["label_set_version"],
    )

    registry = ServiceRegistry()
    registry.register("red", static_service("red_proposal", red_proposal))
    registry.register(
        "platform_execute", static_service("telemetry_evidence", telemetry)
    )
    registry.register(
        "platform_labels", static_service("reviewed_label_set", labels)
    )
    registry.register("platform_baseline", static_service("match_set", baseline))
    registry.register("blue", static_service("blue_proposal", blue_proposal))
    registry.register(
        "platform_compile", static_service("candidate_rule", candidate_rule)
    )
    registry.register(
        "platform_candidate_matches",
        static_service("match_set", candidate_matches),
    )
    registry.register("judge", static_service("judge_result", judge_result))

    outcome = RoundController(repo, registry).run_round(round_request)

    print(f"Database: {DB_NAME}")
    print(f"Round {outcome.task_id}: {outcome.outcome} ({outcome.reason or 'all steps ran'})")
    print("Stored this round:")
    for role, contract in outcome.stored.items():
        print(f"  - {role:26} -> {contract}")
    print(f"  - feedback_record          -> id {outcome.feedback_id}")
    print("\nDocument counts for this task_id:")
    for contract in (
        "round_request",
        "red_proposal",
        "telemetry_evidence",
        "reviewed_label_set",
        "blue_proposal",
        "candidate_rule",
        "match_set",
        "judge_result",
        "feedback_record",
    ):
        query = {"task_id": task_id}
        if contract == "reviewed_label_set":
            query = {"label_set_id": labels["label_set_id"]}
        print(f"  {contract:24} {repo.count(contract, query)}")
    repo.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
