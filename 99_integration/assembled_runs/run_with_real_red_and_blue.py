"""Assembled round: real Red + real Blue + real Platform (Splunk) + real Judge -> MongoDB.

The Orchestrator (01_orchestrator, through shared_services.RoundController)
drives the round. The Platform adapter (99_integration/adapters/platform_service.py)
runs approved, read-only Splunk searches over a frozen, human-reviewed
evaluation set. The deterministic Judge decides acceptance. Nothing in this
runner substitutes fixture evidence.

    python 99_integration/assembled_runs/run_with_real_red_and_blue.py --preflight-only
    python 99_integration/assembled_runs/run_with_real_red_and_blue.py [--provider none|mock|xai|groq]

Live prerequisites (see README.md next to this file): a reachable MongoDB
(AUTOSOC_MONGO_URI / MONGODB_URI, database AUTOSOC_DB, default
``autosoc_assembled``), Splunk settings in the repository .env with TLS
verification enabled, the frozen set indexed in Splunk, and a complete,
human-reviewed label set. Each Splunk search asks the operator to type an
approval bound to that exact search. ``--preflight-only`` makes no network
calls.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from collections.abc import Mapping
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
    ServiceAdapterError,
    WorkflowComponentAdapter,
)

CONTRACTS = REPO_ROOT / "00_shared_contracts"
DEFAULT_EVALUATION_SET = "evalset-demo-lsass-v1"
HOSTED_PROVIDERS = ("xai", "grok", "groq")

# Platform-owned edit constraints for detections with a prepared demo set.
# Other detections need --edit-constraints.
DEFAULT_EDIT_CONSTRAINTS = {
    "67d4dbef-9564-4699-8da8-03a151529edc": {
        "allowed_operations": ["add_exclusion"],
        "allowed_fields": ["SourceImage", "SourceUser", "StartModule", "StartFunction"],
        "attacker_controllable_fields": ["SourceImage"],
        "max_edits": 2,
    },
}


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_adapter(name: str):
    # 99_integration is not an importable name: load the adapter by file path.
    # Register it before execution so dataclasses and adapter-to-adapter
    # imports (platform_service -> blue_service) resolve to one module.
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "99_integration" / "adapters" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def build_round_request(
    prepared_root: Path,
    evaluation_set_id: str,
    *,
    task_id: str,
    detection_id: str | None = None,
    model_id: str,
) -> dict:
    """Freeze a round request from a prepared evaluation set and the shared template.

    The detection and dataset identity come from the prepared set; benign
    constraints, criteria, and prompt versions come from the shared example.
    Labels are not read for content here and are never modified.
    """
    set_dir = prepared_root / evaluation_set_id
    if detection_id is None:
        index = _load_json(set_dir / "detections" / "index.json")
        if len(index) != 1:
            raise ValueError(
                f"{evaluation_set_id} has {len(index)} detections; choose one with --detection-id"
            )
        detection_id = index[0]["detection_id"]
    detection = _load_json(set_dir / "detections" / f"{detection_id}.json")
    labels = _load_json(set_dir / "labels" / "reviewed_label_set.json")
    request = _load_json(CONTRACTS / "round_request" / "examples" / "valid_round_request.json")
    request.pop("permitted_evidence_refs", None)
    request["task_id"] = task_id
    request["detection"] = detection
    request["dataset"] = dict(labels["dataset"])
    request["versions"]["model_id"] = model_id
    return request


def _model_id(provider: str) -> str:
    if provider in ("xai", "grok"):
        return os.environ.get("AUTOSOC_MODEL_ID", "grok-4.7")
    if provider == "groq":
        return os.environ.get("GROQ_MODEL_ID", "openai/gpt-oss-20b")
    return "mock-and-deterministic"


def _hosted_model_refusal(provider: str, label_sources: list[str], allow_public: bool) -> str | None:
    """Explain why Splunk-measured telemetry may not go to a hosted model, if so."""
    if provider not in HOSTED_PROVIDERS:
        return None
    if set(label_sources) != {"public_dataset"}:
        return (
            "the frozen set contains non-public (lab) telemetry; Blue would send its fields "
            "to a hosted model. Use --provider none or mock."
        )
    if not allow_public:
        return (
            "Blue would send Splunk-measured public-dataset fields to a hosted model. "
            "Pass --allow-public-telemetry-to-hosted-model to confirm, or use --provider none."
        )
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--provider",
        default=None,
        choices=("none", "mock", "xai", "grok", "groq"),
        help="Hosted provider: xai/grok requires XAI_API_KEY; groq requires GROQ_API_KEY or GROQ_KEY",
    )
    parser.add_argument("--task-id", default=f"assembled-{uuid4().hex}")
    parser.add_argument("--evaluation-set", default=DEFAULT_EVALUATION_SET)
    parser.add_argument("--detection-id", default=None)
    parser.add_argument("--prepared-root", type=Path, default=None)
    parser.add_argument("--evidence-dir", type=Path, default=None)
    parser.add_argument("--edit-constraints", type=Path, default=None,
                        help="JSON edit_constraints for Blue (required for detections without a default)")
    parser.add_argument("--earliest-time", default="0",
                        help="Splunk earliest_time for every search (default: all time)")
    parser.add_argument("--latest-time", default="now")
    parser.add_argument("--allow-public-telemetry-to-hosted-model", action="store_true")
    parser.add_argument("--preflight-only", action="store_true",
                        help="Check configuration, labels, and rule scope; no network calls")
    args = parser.parse_args(argv)

    platform_module = _load_adapter("platform_service")
    prepared_root = args.prepared_root or platform_module.DEFAULT_PREPARED_ROOT
    provider = (args.provider or os.environ.get("AUTOSOC_MODEL_PROVIDER") or "").strip().lower()

    try:
        round_request = build_round_request(
            prepared_root, args.evaluation_set,
            task_id=args.task_id, detection_id=args.detection_id, model_id=_model_id(provider),
        )
    except (OSError, ValueError, KeyError) as exc:
        print(f"Cannot freeze a round request from {args.evaluation_set!r}: {exc}")
        return 2
    detection_id = round_request["detection"]["detection_id"]
    if args.edit_constraints is not None:
        edit_constraints = _load_json(args.edit_constraints)
    elif detection_id in DEFAULT_EDIT_CONSTRAINTS:
        edit_constraints = DEFAULT_EDIT_CONSTRAINTS[detection_id]
    else:
        print(f"No default edit constraints for {detection_id}; pass --edit-constraints FILE.")
        return 2

    try:
        platform = platform_module.build_splunk_platform_service(
            edit_constraints=edit_constraints,
            prepared_root=prepared_root,
            evidence_dir=args.evidence_dir or platform_module.DEFAULT_EVIDENCE_DIR,
            earliest_time=args.earliest_time,
            latest_time=args.latest_time,
        )
    except ValueError as exc:
        print(f"Platform configuration refused: {exc}")
        return 2

    try:
        readiness = platform.preflight(round_request)
    except ServiceAdapterError as exc:
        print(f"Platform preflight failed ({exc.category}): {exc}")
        print("No round was opened and no Splunk search was requested.")
        return 2
    refusal = _hosted_model_refusal(
        provider, readiness["label_sources"], args.allow_public_telemetry_to_hosted_model
    )
    if refusal:
        print(f"Refusing provider {provider!r}: {refusal}")
        return 2
    print(f"Platform preflight passed for {readiness['label_set_id']} "
          f"({readiness['total_events']} reviewed events).")
    print(f"  telemetry SPL: {readiness['telemetry_spl']}")
    print(f"  baseline SPL:  {readiness['baseline_spl']}")
    if args.preflight_only:
        return 0

    from shared_services.datastore.repository import MongoRepository

    red_service = _load_adapter("red_service")
    blue_service = _load_adapter("blue_service")
    judge_service = _load_adapter("judge_service")

    repo = MongoRepository(db_name=os.environ["AUTOSOC_DB"], fallback_to_mock=False)
    if repo.backend != "mongodb":
        raise RuntimeError("The assembled run requires a persistent MongoDB backend")
    repo.ping()
    repo.ensure_setup()
    task_id = round_request["task_id"]

    services = SimpleNamespace(
        red=WorkflowComponentAdapter(
            red_service.build_red_service(provider=args.provider), "red_proposal"
        ),
        blue=WorkflowComponentAdapter(
            blue_service.build_blue_service(provider=args.provider), "blue_proposal"
        ),
        platform=platform,
        judge=WorkflowComponentAdapter(
            judge_service.build_judge_service(), "judge_result"
        ),
    )
    try:
        outcome = RoundController(repo, services).run_round(round_request)
        record = outcome.record
        print(f"Round {task_id}: {outcome.state}")
        for artifact, reference in sorted(record.artifacts.items()):
            print(f"  - {artifact:24} -> {reference}")
        error = getattr(record, "error", None)
        if isinstance(error, Mapping):
            print(f"Round error ({error.get('category')}): {error.get('message')}")
        judge_rows = repo.find_by_task("judge_result", task_id)
        if judge_rows:
            print(f"Judge decision (measured on Splunk results): {judge_rows[-1]['decision']['status']}")
        else:
            print("No Judge decision: the round stopped before evaluation.")
        blue = repo.find_by_task("blue_proposal", task_id)
        if blue:
            _report_blue(blue[-1])
        return 0 if outcome.state in {"completed", "inconclusive"} else 1
    finally:
        repo.close()


def _report_blue(proposal: dict) -> None:
    """Show the exact Blue proposal stored by the workflow."""
    print(f"\nBlue proposal stored: {proposal['proposal_id']}")
    for e in proposal["edits"]:
        conds = " AND ".join(f"{c['field']} {c['modifier']} {c['values']}" for c in e["conditions"])
        print(f"  {e['operation']}: {conds}")


if __name__ == "__main__":
    raise SystemExit(main())
