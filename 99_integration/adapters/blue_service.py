"""Adapt the real Blue component to the Orchestrator workflow service interface.

``build_blue_service`` plugs the real Blue component (03_blue_role, package
``autosoc_blue``) into the shared Orchestrator workflow.

``blue_input_from_context`` is retained as a development/evidence adapter. The
Orchestrator owns the workflow order and invokes Blue only after its platform
service has verified evidence.

Packaging: ``autosoc_blue`` is a normal installable package (``pip install -e
03_blue_role``). If it is not installed, this adapter appends ``03_blue_role`` to the END
of ``sys.path`` (never the front: 02_red_role also has top-level ``schemas/``).
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
from pathlib import Path

from shared_services.controller.services import CallableService, ServiceResult

REPO_ROOT = Path(__file__).resolve().parents[2]
BLUE_ROOT = REPO_ROOT / "03_blue_role"
ADAPTER_ROOT = Path(__file__).resolve().parent
DEFAULT_EVIDENCE_FIXTURE = BLUE_ROOT / "dev" / "fixtures" / "inputs" / "single_fp.json"
BLUE_PROMPT_VERSION = "blue-system@0.1.0"
PLATFORM_EVIDENCE_ROLES = {
    "platform_execute",
    "platform_labels",
    "platform_baseline",
}

if str(ADAPTER_ROOT) not in sys.path:
    sys.path.append(str(ADAPTER_ROOT))

from model_gateway_service import build_platform_gateway, for_blue


def _ensure_blue_importable() -> None:
    try:
        import autosoc_blue  # noqa: F401
    except ImportError:
        sp = str(BLUE_ROOT)
        if sp not in sys.path:
            sys.path.append(sp)


def build_blue_service(
    engine=None, *, provider: str | None = None, gateway=None
) -> CallableService:
    """Return a Service backed by the real BlueRole.

    ``engine`` is any BlueEngine. If omitted, one is built from the environment
    (``AUTOSOC_MODEL_PROVIDER`` for Platform-hosted models; otherwise Blue's
    standalone provider selection, which defaults to deterministic).
    """
    _ensure_blue_importable()
    from autosoc_blue import BlueRole, build_engine

    selected_provider = (
        provider or os.environ.get("AUTOSOC_MODEL_PROVIDER") or ""
    ).strip().lower()
    if engine is None and (
        gateway is not None or selected_provider in ("xai", "grok", "groq")
    ):
        from autosoc_blue.adapters.llm import LLMProposer
        from autosoc_blue.core.engine import BlueEngine

        hosted_gateway = gateway or build_platform_gateway(selected_provider)
        engine = BlueEngine(LLMProposer(for_blue(hosted_gateway)))

    blue = BlueRole(engine or build_engine(provider))

    def handle(payload: dict) -> ServiceResult:
        result = blue.run(payload)
        contract = "blue_proposal" if "edits" in result else "error_response"
        return ServiceResult(contract=contract, payload=result)

    return CallableService(handle)


def blue_input_from_context(ctx: dict, evidence_fixture: Path | str = DEFAULT_EVIDENCE_FIXTURE) -> dict:
    """Build a blue_input from Platform outputs, or the dev fixture when unconnected."""
    rr = ctx.get("round_request", {})
    base = json.loads(Path(evidence_fixture).read_text(encoding="utf-8"))
    blue_input = copy.deepcopy(base)
    blue_input["task_id"] = ctx.get("task_id") or rr.get("task_id") or base["task_id"]
    blue_input["prompt_version"] = (
        rr.get("versions", {}).get("blue_prompt")
        or rr.get("blue_prompt_version")
        or BLUE_PROMPT_VERSION
    )
    detection = rr.get("detection", {})
    for key in ("detection_id", "rule_version", "logic_summary"):
        if detection.get(key):
            blue_input["detection"][key] = detection[key]
    if detection.get("rule_text"):
        blue_input["detection"]["rule_text"] = detection["rule_text"]
    if detection.get("rule_language") == "splunk_spl":
        blue_input["detection"]["rule_format"] = "spl"
    elif detection.get("rule_language") == "sigma":
        blue_input["detection"]["rule_format"] = "sigma"

    results = ctx.get("results", {})
    present_roles = PLATFORM_EVIDENCE_ROLES.intersection(results)
    if present_roles and present_roles != PLATFORM_EVIDENCE_ROLES:
        missing = sorted(PLATFORM_EVIDENCE_ROLES - present_roles)
        raise ValueError(f"Platform evidence is incomplete; missing results: {missing}")
    if present_roles:
        _apply_platform_evidence(blue_input, rr, results)
    return blue_input


def _apply_platform_evidence(blue_input: dict, round_request: dict, results: dict) -> None:
    false_positives, must_detect = platform_evidence_cases(
        round_request,
        results["platform_execute"].payload,
        results["platform_labels"].payload,
        results["platform_baseline"].payload,
        task_id=blue_input["task_id"],
        detection_id=blue_input["detection"]["detection_id"],
    )
    blue_input["false_positives"] = false_positives
    blue_input["must_detect"] = must_detect


_EVENT_METADATA_FIELDS = ("host", "source", "sourcetype")


def platform_evidence_cases(
    round_request: dict,
    telemetry: dict,
    labels: dict,
    baseline: dict,
    *,
    task_id: str,
    detection_id: str,
    observed_fields: list[str] | tuple[str, ...] | None = None,
) -> tuple[list[dict], list[dict]]:
    """Join verified telemetry, reviewed labels, and baseline matches into Blue cases.

    False positives are reviewed benign events the baseline matched; must-detect
    cases are every reviewed attack event. Event identity is ``event_id`` in all
    three artifacts.

    ``observed_fields`` limits what each case copies from the event: only the
    named fields are taken from ``fields`` (or from the event's host/source/
    sourcetype metadata), so Blue receives what it may reason about and no
    other telemetry. Without it, every event field is copied.
    """
    from shared_services.datastore.validation import validate

    for contract, payload in (
        ("telemetry_evidence", telemetry),
        ("reviewed_label_set", labels),
        ("match_set", baseline),
    ):
        validation_result = validate(payload, contract)
        if validation_result is None or not validation_result.ok:
            detail = "no schema published" if validation_result is None else validation_result.summary()
            raise ValueError(f"Platform {contract} is invalid: {detail}")

    original_evidence = {
        key: value for key, value in telemetry.items() if key != "content_sha256"
    }
    expected_hash = hashlib.sha256(
        json.dumps(
            original_evidence,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    if telemetry["content_sha256"] != expected_hash:
        raise ValueError("Platform telemetry failed content-hash verification")

    dataset = round_request.get("dataset")
    if telemetry.get("task_id") != task_id or telemetry.get("detection_id") != detection_id:
        raise ValueError("Platform telemetry does not match the round task and detection")
    if labels.get("dataset") != dataset or baseline.get("dataset") != dataset:
        raise ValueError("Platform labels and baseline matches must use the frozen round dataset")
    if baseline.get("task_id") != task_id or baseline.get("detection_id") != detection_id:
        raise ValueError("Platform baseline matches do not match the round task and detection")
    if baseline.get("role") != "baseline":
        raise ValueError("Blue requires the baseline match set, not candidate matches")
    if labels.get("coverage", {}).get("complete") is not True:
        raise ValueError("Blue requires a complete reviewed label set")
    if labels["coverage"]["total_events"] != len(labels["labels"]):
        raise ValueError("Platform label coverage count does not match the reviewed labels")

    event_by_id = {}
    for event in telemetry.get("events", []):
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or event_id in event_by_id:
            raise ValueError("Platform telemetry contains a missing or duplicate event_id")
        fields = event.get("fields")
        if observed_fields is None:
            if not isinstance(fields, dict) or not fields:
                raise ValueError(f"Platform telemetry event {event_id!r} has no fields")
            if any(not isinstance(value, str) for value in fields.values()):
                raise ValueError(f"Platform telemetry event {event_id!r} has non-string fields")
            event_by_id[event_id] = fields
        else:
            if not isinstance(fields, dict):
                raise ValueError(f"Platform telemetry event {event_id!r} has no fields")
            event_by_id[event_id] = event

    def observed(event_id: str) -> dict:
        if observed_fields is None:
            return event_by_id[event_id]
        event = event_by_id[event_id]
        projected = {}
        for name in observed_fields:
            if name in event["fields"]:
                value = event["fields"][name]
            elif name in _EVENT_METADATA_FIELDS and name in event:
                value = event[name]
            else:
                continue
            if not isinstance(value, str):
                raise ValueError(
                    f"Platform telemetry event {event_id!r} field {name!r} is not a single string value"
                )
            projected[name] = value
        if not projected:
            raise ValueError(
                f"Platform telemetry event {event_id!r} has none of the fields Blue may observe"
            )
        return projected

    baseline_match_ids = {
        match["event_id"] for match in baseline.get("matches", [])
    }
    false_positives = []
    must_detect = []
    for label in labels.get("labels", []):
        event_id = label["event_id"]
        if label.get("review", {}).get("status") != "reviewed":
            raise ValueError(f"Platform label for event {event_id!r} is not reviewed")
        is_false_positive = label["label"] == "benign" and event_id in baseline_match_ids
        is_must_detect = label["label"] == "attack"
        if not is_false_positive and not is_must_detect:
            continue
        if event_id not in event_by_id:
            raise ValueError(
                f"Platform telemetry is missing labelled event {event_id!r}"
            )
        case = {
            "evidence_reference": {
                "evidence_id": telemetry["evidence_id"],
                "evidence_type": "telemetry",
                "provenance_ref": (
                    f"evidence_store:{telemetry['evidence_id']}#{event_id};"
                    f"reviewed_label_set:{labels['label_set_id']}#{event_id}"
                ),
            },
            "observed_fields": observed(event_id),
        }
        scenario_id = label.get("scenario_id")
        if scenario_id:
            case["label_note"] = f"Reviewed scenario: {scenario_id}"
        (false_positives if is_false_positive else must_detect).append(case)
    if not false_positives or not must_detect:
        raise ValueError(
            "Platform evidence must include a baseline-matched benign event "
            "and at least one reviewed attack event"
        )
    return false_positives, must_detect
