"""Assembled round: REAL Red + REAL Blue + real Judge, mock Platform -> MongoDB.

Red (02_red_role), Blue (03_blue_role, package ``autosoc_blue``), and the
deterministic Judge (04_deterministic_judge) are wired through adapters. Platform
outputs are smoke-test fixtures, not real Splunk measurements. The fixture
contains no baseline attack matches, so the real Judge returns INCONCLUSIVE
rather than an acceptance decision. Everything each service returns is
validated and stored in MongoDB.

    # from the repo root (a MongoDB must be reachable, see AUTOSOC_MONGO_URI):
    docker run -d --name autosoc-mongo -p 27017:27017 mongo:7
    python 99_integration/assembled_runs/run_with_real_red_and_blue.py [--provider none|mock|xai|groq]

Blue uses its deterministic proposer unless a provider is given (or
AUTOSOC_MODEL_PROVIDER is set). The xAI provider uses XAI_API_KEY; the Groq
provider uses GROQ_API_KEY or GROQ_KEY. Platform execution remains a mock.
The database name defaults to ``autosoc_assembled`` (override with AUTOSOC_DB) so the
shared ``autosoc`` database is not touched.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
os.environ.setdefault("AUTOSOC_DB", "autosoc_assembled")

ORCHESTRATOR_ROOT = REPO_ROOT / "01_orchestrator"
if str(ORCHESTRATOR_ROOT) not in sys.path:
    sys.path.append(str(ORCHESTRATOR_ROOT))

from shared_services.controller.round_controller import RoundController  # noqa: E402
from shared_services.controller.services import (  # noqa: E402
    ServiceResult,
    WorkflowComponentAdapter,
)
from shared_services.datastore.repository import MongoRepository  # noqa: E402

_workflow_models = import_module("workflow.models")
BlueInputContext = _workflow_models.BlueInputContext
WorkflowStepOutput = _workflow_models.WorkflowStepOutput


CONTRACTS = REPO_ROOT / "00_shared_contracts"
BLUE_FIXTURE = (
    REPO_ROOT / "03_blue_role" / "dev" / "fixtures" / "inputs" / "single_fp.json"
)


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _build_mock_evidence(request: dict, red_proposal: dict) -> dict:
    """Build contract-valid smoke evidence from the reviewed Blue fixture."""
    task_id = request["task_id"]
    fixture = _load_json(BLUE_FIXTURE)
    events = []
    labels = []
    event_ids = []
    benign_event_ids = []
    cases = [
        *((case, "benign") for case in fixture["false_positives"]),
        *((case, "attack") for case in fixture["must_detect"]),
    ]
    for index, (case, label) in enumerate(cases, start=1):
        event_id = f"{task_id}-event-{index}"
        event_ids.append(event_id)
        events.append(
            {
                "event_id": event_id,
                "timestamp": "2026-11-10T09:00:00Z",
                "fields": case["observed_fields"],
            }
        )
        labels.append(
            {
                "event_id": event_id,
                "label": label,
                "source": "lab_telemetry",
                "scenario_id": f"{task_id}-scenario-{index}",
                "review": {
                    "status": "reviewed",
                    "reviewer": "assembled-smoke-fixture",
                    "reviewed_at": "2026-11-10T09:00:00Z",
                },
            }
        )
        if label == "benign":
            benign_event_ids.append(event_id)

    telemetry = {
        "contract_version": "0.1.0",
        "evidence_id": f"evidence-{task_id}",
        "task_id": task_id,
        "proposal_id": red_proposal["proposal_id"],
        "detection_id": request["detection"]["detection_id"],
        "source": "splunk",
        "execution": {
            "execution_id": f"execution-{task_id}",
            "status": "succeeded",
            "operation_id": f"operation-{task_id}",
            "approval_id": f"approval-{task_id}",
            "started_at": "2026-11-10T09:00:00Z",
            "completed_at": "2026-11-10T09:00:01Z",
            "event_count": len(events),
            "truncated": False,
        },
        "events": events,
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

    label_set = {
        "contract_version": "0.1.0",
        "label_set_id": f"labels-{task_id}",
        "label_set_version": "1",
        "dataset": request["dataset"],
        "coverage": {"total_events": len(labels), "complete": True},
        "labels": labels,
    }
    baseline = _load_json(
        CONTRACTS / "candidate_rule" / "examples" / "valid_match_set.json"
    )
    baseline.update(
        match_set_id=f"baseline-{task_id}",
        task_id=task_id,
        role="baseline",
        detection_id=request["detection"]["detection_id"],
        rule_version=request["detection"]["rule_version"],
        dataset=request["dataset"],
        matches=[{"event_id": event_id, "index": "lab_eval"} for event_id in benign_event_ids],
    )
    baseline["execution"]["execution_id"] = f"baseline-execution-{task_id}"
    baseline["execution"]["status"] = "completed"
    baseline.pop("candidate_ref", None)
    return {"telemetry": telemetry, "labels": label_set, "baseline": baseline}


def _load_adapter(name: str):
    # 99_integration is not an importable name: load the adapter by file path.
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "99_integration" / "adapters" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SmokeTestPlatform:
    """Provide explicit, partial fixture evidence through the Platform interface."""

    def __init__(self, blue_adapter):
        self.blue_adapter = blue_adapter
        self.evidence = {}

    def collect_telemetry(self, round_request, _red_proposal):
        task_id = round_request["task_id"]
        return WorkflowStepOutput(
            raw_output_ref=f"smoke://telemetry/{task_id}",
            raw_output={
                "task_id": task_id,
                "source": "fixture",
                "red_proposal_id": _red_proposal["proposal_id"],
            },
            detail="smoke-test fixture collection; not a Splunk execution",
        )

    def verify_evidence(self, round_request, red_proposal, telemetry_ref):
        expected_ref = f"smoke://telemetry/{round_request['task_id']}"
        if telemetry_ref != expected_ref:
            raise ValueError(f"Unexpected smoke telemetry reference: {telemetry_ref!r}")
        self.evidence = _build_mock_evidence(round_request, red_proposal)
        return WorkflowStepOutput(
            messages={
                "telemetry_evidence": self.evidence["telemetry"],
                "reviewed_label_set": self.evidence["labels"],
                "baseline_match_set": self.evidence["baseline"],
            },
            raw_output={"telemetry_ref": telemetry_ref, "fixture_verified": True},
            detail="contract-valid fixture evidence; baseline has no attack matches",
        )

    def build_blue_context(self, round_request, artifacts):
        task_id = round_request["task_id"]
        context = self.blue_adapter.blue_input_from_context(
            {
                "task_id": task_id,
                "round_request": dict(round_request),
                "results": {
                    "platform_execute": ServiceResult(
                        "telemetry_evidence", dict(artifacts["telemetry_evidence"])
                    ),
                    "platform_labels": ServiceResult(
                        "reviewed_label_set", dict(artifacts["reviewed_label_set"])
                    ),
                    "platform_baseline": ServiceResult(
                        "match_set", dict(artifacts["baseline_match_set"])
                    ),
                },
            }
        )
        return BlueInputContext(
            evidence_view={
                "task_id": context["task_id"],
                "detection_id": context["detection"]["detection_id"],
                "false_positives": context["false_positives"],
                "must_detect": context["must_detect"],
            },
            edit_constraints=context["edit_constraints"],
            blue_detection=context["detection"],
            prior_blue_edits=context.get("prior_blue_edits"),
        )

    def execute_candidate(self, round_request, blue_proposal, baseline_match_set):
        if baseline_match_set is None:
            raise ValueError("Smoke candidate execution requires the verified baseline set")
        candidate = {}
        candidate_rule = _compile_mock(
            {
                "task_id": round_request["task_id"],
                "round_request": dict(round_request),
                "blue_proposal": dict(blue_proposal),
            },
            candidate,
            dict(round_request),
        )
        candidate["matches"]["matches"] = [dict(match) for match in baseline_match_set["matches"]]
        return WorkflowStepOutput(
            messages={
                "candidate_rule": candidate_rule.payload,
                "candidate_match_set": candidate["matches"],
            },
            raw_output={
                "candidate_execution_id": candidate["matches"]["execution"]["execution_id"],
                "measurement_status": "fixture",
            },
            detail="candidate fixture has no baseline attack matches; Judge must return INCONCLUSIVE",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--provider",
        default=None,
        choices=("none", "mock", "xai", "grok", "groq"),
        help="Hosted provider: xai/grok requires XAI_API_KEY; groq requires GROQ_API_KEY or GROQ_KEY",
    )
    parser.add_argument("--task-id", default=f"assembled-{uuid4().hex}")
    args = parser.parse_args(argv)

    red_service = _load_adapter("red_service")
    blue_service = _load_adapter("blue_service")
    judge_service = _load_adapter("judge_service")

    repo = MongoRepository(
        db_name=os.environ["AUTOSOC_DB"], fallback_to_mock=False
    )
    if repo.backend != "mongodb":
        raise RuntimeError("The assembled run requires a persistent MongoDB backend")
    repo.ping()
    repo.ensure_setup()
    task_id = args.task_id

    round_request = _load_json(
        CONTRACTS / "round_request" / "examples" / "valid_round_request.json"
    )
    round_request["task_id"] = task_id
    selected_provider = (
        args.provider or os.environ.get("AUTOSOC_MODEL_PROVIDER") or ""
    ).strip().lower()
    if selected_provider in ("xai", "grok"):
        round_request["versions"]["model_id"] = os.environ.get(
            "AUTOSOC_MODEL_ID", "grok-4.7"
        )
    elif selected_provider == "groq":
        round_request["versions"]["model_id"] = os.environ.get(
            "GROQ_MODEL_ID", "openai/gpt-oss-20b"
        )
    else:
        round_request["versions"]["model_id"] = "mock-and-deterministic"
    services = SimpleNamespace(
        red=WorkflowComponentAdapter(
            red_service.build_red_service(provider=args.provider), "red_proposal"
        ),
        blue=WorkflowComponentAdapter(
            blue_service.build_blue_service(provider=args.provider), "blue_proposal"
        ),
        platform=SmokeTestPlatform(blue_service),
        judge=WorkflowComponentAdapter(
            judge_service.build_judge_service(), "judge_result"
        ),
    )
    outcome = RoundController(repo, services).run_round(round_request)
    record = outcome.record
    print(f"Round {task_id}: {outcome.state}")
    for artifact, reference in sorted(record.artifacts.items()):
        print(f"  - {artifact:24} -> {reference}")
    judge_rows = repo.find_by_task("judge_result", task_id)
    if judge_rows:
        print(f"Judge decision: {judge_rows[-1]['decision']['status']}")
    print(
        "\nSMOKE TEST ONLY: Platform evidence and candidate execution are "
        "fixtures. The deterministic Judge ran, but there are no baseline "
        "attack matches; this cannot produce an acceptance verdict or represent "
        "measured Splunk results."
    )

    exit_code = 0 if outcome.state in {"completed", "inconclusive"} else 1
    red = repo.find_by_task("red_proposal", task_id)
    if red:
        print(f"\nReal red_proposal stored: {red[-1]['proposal_id']} ({red[-1]['scenario']['family']})")

    blue = repo.find_by_task("blue_proposal", task_id)
    if blue:
        _report_blue(blue[-1])
    else:
        print("\nNo blue_proposal stored.")
        exit_code = 1
    repo.close()
    return exit_code


def _compile_mock(payload: dict, candidate: dict, request: dict) -> ServiceResult:
    proposal = payload["blue_proposal"]
    candidate_rule = _load_json(
        CONTRACTS / "candidate_rule" / "examples" / "valid_candidate_rule.json"
    )
    candidate_id = f"candidate-{payload['task_id']}"
    candidate_version = f"{request['detection']['rule_version']}-candidate-1"
    candidate_rule.update(
        candidate_id=candidate_id,
        task_id=payload["task_id"],
        proposal_id=proposal["proposal_id"],
        detection_id=request["detection"]["detection_id"],
        base_rule_version=request["detection"]["rule_version"],
        candidate_rule_version=candidate_version,
        applied_edit_count=len(proposal["edits"]),
    )
    candidate["rule"] = candidate_rule

    matches = _load_json(
        CONTRACTS / "candidate_rule" / "examples" / "valid_match_set.json"
    )
    matches.update(
        match_set_id=f"candidate-matches-{payload['task_id']}",
        task_id=payload["task_id"],
        role="candidate",
        detection_id=request["detection"]["detection_id"],
        rule_version=candidate_version,
        candidate_ref=candidate_id,
        dataset=request["dataset"],
    )
    matches["execution"]["execution_id"] = f"candidate-execution-{payload['task_id']}"
    matches["execution"]["status"] = "completed"
    candidate["matches"] = matches
    return ServiceResult("candidate_rule", candidate_rule)


def _report_blue(proposal: dict) -> None:
    """Show the exact Blue proposal stored by the workflow."""
    print(f"\nReal blue_proposal stored: {proposal['proposal_id']}")
    for e in proposal["edits"]:
        conds = " AND ".join(f"{c['field']} {c['modifier']} {c['values']}" for c in e["conditions"])
        print(f"  {e['operation']}: {conds}")


if __name__ == "__main__":
    raise SystemExit(main())
