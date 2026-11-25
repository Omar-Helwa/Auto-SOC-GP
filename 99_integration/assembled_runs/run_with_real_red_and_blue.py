"""Assembled round: REAL Red + REAL Blue, contract-valid Platform/Judge mocks -> MongoDB.

Red (02_red_role) and Blue (03_blue_role, package ``autosoc_blue``) are wired
through their adapters. Platform and Judge outputs are smoke-test fixtures, not
real Splunk measurements or an acceptance decision. Everything each service
returns is validated and stored in MongoDB.

    # from the repo root (a MongoDB must be reachable, see AUTOSOC_MONGO_URI):
    docker run -d --name autosoc-mongo -p 27017:27017 mongo:7
    python 99_integration/assembled_runs/run_with_real_red_and_blue.py [--provider none|mock|xai|groq]

Blue uses its deterministic proposer unless a provider is given (or
AUTOSOC_MODEL_PROVIDER is set). The xAI provider uses XAI_API_KEY; the Groq
provider uses GROQ_API_KEY or GROQ_KEY. Platform execution and judge
are still mocks.
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
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
os.environ.setdefault("AUTOSOC_DB", "autosoc_assembled")

from shared_services.controller.round_controller import (  # noqa: E402
    RoundController,
    RoundStep,
)
from shared_services.controller.services import (  # noqa: E402
    CallableService,
    ServiceRegistry,
    ServiceResult,
)
from shared_services.datastore.repository import MongoRepository  # noqa: E402


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
        matches=[{"event_id": event_id, "index": "lab_eval"} for event_id in event_ids],
    )
    baseline["execution"]["execution_id"] = f"baseline-execution-{task_id}"
    baseline.pop("candidate_ref", None)
    return {"telemetry": telemetry, "labels": label_set, "baseline": baseline}


def _load_adapter(name: str):
    # 99_integration is not an importable name: load the adapter by file path.
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "99_integration" / "adapters" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--provider",
        default=None,
        choices=("none", "mock", "xai", "grok", "groq"),
        help="Hosted provider: xai/grok requires XAI_API_KEY; groq requires GROQ_API_KEY or GROQ_KEY",
    )
    parser.add_argument("--task-id", default="assembled-real-red-blue-0001")
    args = parser.parse_args(argv)

    red_service = _load_adapter("red_service")
    blue_service = _load_adapter("blue_service")

    repo = MongoRepository(db_name=os.environ["AUTOSOC_DB"])
    repo.ping()
    repo.ensure_setup()
    task_id = args.task_id

    registry = ServiceRegistry()
    registry.register("red", red_service.build_red_service(provider=args.provider))  # REAL Red
    registry.register("blue", blue_service.build_blue_service(provider=args.provider))  # REAL Blue
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
    evidence = {}
    candidate = {}
    registry.register(
        "platform_execute",
        CallableService(
            lambda payload: _execute_mock(payload, evidence)
        ),
    )
    registry.register(
        "platform_labels",
        CallableService(
            lambda _payload: ServiceResult("reviewed_label_set", evidence["labels"])
        ),
    )
    registry.register(
        "platform_baseline",
        CallableService(
            lambda _payload: ServiceResult("match_set", evidence["baseline"])
        ),
    )
    registry.register(
        "platform_compile",
        CallableService(
            lambda payload: _compile_mock(payload, candidate, round_request)
        ),
    )
    registry.register(
        "platform_candidate_matches",
        CallableService(
            lambda _payload: ServiceResult("match_set", candidate["matches"])
        ),
    )
    registry.register(
        "judge",
        CallableService(
            lambda payload: ServiceResult(
                "judge_result", _inconclusive_mock_judgment(payload["task_id"])
            )
        ),
    )

    steps = blue_service.blue_round_steps()
    custom_builders = {
        "platform_execute": lambda ctx: {
            "task_id": ctx["task_id"],
            "round_request": ctx["round_request"],
            "red_proposal": ctx["results"]["red"].payload,
        },
        "platform_compile": lambda ctx: {
            "task_id": ctx["task_id"],
            "round_request": ctx["round_request"],
            "blue_proposal": ctx["results"]["blue"].payload,
        },
    }
    for index, step in enumerate(steps):
        if step.role in custom_builders:
            steps[index] = RoundStep(
                step.role, custom_builders[step.role], step.label
            )
    controller = RoundController(repo, registry, steps=steps)
    outcome = controller.run_round(round_request)
    print(f"Round {outcome.task_id}: {outcome.outcome} ({outcome.reason or 'all steps ran'})")
    for role, contract in outcome.stored.items():
        print(f"  - {role:18} -> {contract}")
    print(
        "\nSMOKE TEST ONLY: Platform evidence, candidate execution, and the "
        "INCONCLUSIVE judge response are fixtures; no Splunk measurement or "
        "acceptance verdict was produced."
    )

    exit_code = 0 if outcome.outcome == "completed" else 1
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


def _execute_mock(payload: dict, evidence: dict) -> ServiceResult:
    evidence.update(_build_mock_evidence(payload["round_request"], payload["red_proposal"]))
    return ServiceResult("telemetry_evidence", evidence["telemetry"])


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
    candidate["matches"] = matches
    return ServiceResult("candidate_rule", candidate_rule)


def _inconclusive_mock_judgment(task_id: str) -> dict:
    return {
        "contract_version": "0.1.0",
        "judge_input_id": f"mock-judge-{task_id}",
        "task_id": task_id,
        "decision": {
            "status": "INCONCLUSIVE",
            "reasons": ["Mock outputs are not measured execution evidence."],
            "failed_gates": [],
            "failures": [
                {
                    "code": "INPUT",
                    "kind": "incomplete",
                    "message": "Smoke-test fixtures cannot support an acceptance verdict.",
                }
            ],
        },
    }


def _report_blue(proposal: dict) -> None:
    """Show the stored proposal and re-check it against the reviewed events (read back from MongoDB)."""
    from autosoc_blue.adapters.validators import LocalSigmaValidator
    from autosoc_blue.rule_edits import apply_edits
    from autosoc_blue.schemas.models import BlueInput, BlueProposal

    blue_service = _load_adapter("blue_service")
    blue_input = blue_service.blue_input_from_context({"task_id": proposal["task_id"], "round_request": {}})
    inp = BlueInput.from_dict(blue_input)
    cand = apply_edits(inp.detection.rule_text, BlueProposal.from_dict(proposal).edits)
    v = LocalSigmaValidator()
    print(f"\nReal blue_proposal stored: {proposal['proposal_id']}")
    for e in proposal["edits"]:
        conds = " AND ".join(f"{c['field']} {c['modifier']} {c['values']}" for c in e["conditions"])
        print(f"  {e['operation']}: {conds}")
    for fp in inp.false_positives:
        print(f"  false positive {fp.evidence_id}: still matched = {v.matches(cand.rule_text, fp.observed_fields)}")
    for m in inp.must_detect:
        print(f"  must-detect    {m.evidence_id}: still matched = {v.matches(cand.rule_text, m.observed_fields)}")
    print("\nCandidate rule diff:\n" + cand.diff)


if __name__ == "__main__":
    raise SystemExit(main())
