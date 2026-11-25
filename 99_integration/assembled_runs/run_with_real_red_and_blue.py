"""Assembled round: REAL Red + REAL Blue, mocks for platform/judge -> MongoDB.

Red (02_red_role) and Blue (03_blue_role, package ``autosoc_blue``) are wired
through their adapters. The platform and the judge are still mocks. Everything
each service returns is validated and stored in MongoDB; the Blue proposal is
read back and checked against the reviewed events with Blue's local matcher.

    # from the repo root (a MongoDB must be reachable, see AUTOSOC_MONGO_URI):
    docker run -d --name autosoc-mongo -p 27017:27017 mongo:7
    python 99_integration/assembled_runs/run_with_real_red_and_blue.py [--provider mock|anthropic|openai]

Blue uses its deterministic proposer unless a provider is given (or BLUE_MODEL_PROVIDER is set).
The database name defaults to ``autosoc_assembled`` (override with AUTOSOC_DB) so the
shared ``autosoc`` database is not touched.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
os.environ.setdefault("AUTOSOC_DB", "autosoc_assembled")

from shared_services.controller.round_controller import RoundController  # noqa: E402
from shared_services.controller.services import ServiceRegistry, static_service  # noqa: E402
from shared_services.datastore.repository import MongoRepository  # noqa: E402


def _load_adapter(name: str):
    # 99_integration is not an importable name: load the adapter by file path.
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "99_integration" / "adapters" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--provider", default=None, choices=("none", "mock", "anthropic", "openai"),
                        help="Blue model provider (default: deterministic, no AI)")
    parser.add_argument("--task-id", default="assembled-real-red-blue-0001")
    args = parser.parse_args(argv)

    red_service = _load_adapter("red_service")
    blue_service = _load_adapter("blue_service")

    repo = MongoRepository(db_name=os.environ["AUTOSOC_DB"])
    repo.ping()
    repo.ensure_setup()
    task_id = args.task_id

    registry = ServiceRegistry()
    registry.register("red", red_service.build_red_service())              # REAL Red (mock model inside)
    registry.register("blue", blue_service.build_blue_service(provider=args.provider))  # REAL Blue
    registry.register("platform_execute", static_service(
        "telemetry_evidence", lambda _p: {"task_id": task_id, "evidence": "mock-telemetry"}))
    registry.register("platform_compile", static_service(
        "candidate_rule", lambda _p: {"task_id": task_id, "rule": "mock-candidate"}))
    registry.register("judge", static_service(
        "judge_result", lambda _p: {"task_id": task_id, "decision": "pass"}))

    round_request = {
        "task_id": task_id,
        "detection": {
            "detection_id": "win-encoded-powershell",
            "rule_version": "3.2.0",
            "logic_summary": "PowerShell or pwsh process whose command line contains -enc or -EncodedCommand.",
        },
        "benign_constraints": {
            "allowed_scenario_families": ["admin_automation", "it_maintenance"],
            "max_workflow_steps": 5,
            "allowed_actions": ["scheduled_task", "script_execution", "process_execution"],
        },
        "prompt_version": "red-system@0.1.0",
    }

    controller = RoundController(repo, registry, steps=blue_service.blue_round_steps())
    outcome = controller.run_round(round_request)
    print(f"Round {outcome.task_id}: {outcome.outcome} ({outcome.reason or 'all steps ran'})")
    for role, contract in outcome.stored.items():
        print(f"  - {role:18} -> {contract}")

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
