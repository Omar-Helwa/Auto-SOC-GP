from typing import Any, Mapping

from interfaces.inputs.input_validator import validate_judge_input
from match_sets.match_processing import (
    compare_matches,
    normalize_by_event_id,
)
from metrics.metrics import calculate_metrics
from reports.report_builder import build_report
from .mandatory_gates import evaluate_gates

def _inconclusive(value: Mapping[str, Any], errors: list[str]):
    return {
        "judge_input_id": value.get("judge_input_id"),
        "task_id": value.get("task_id"),
        "decision": {"status": "INCONCLUSIVE", "reasons": errors, "failed_gates": []},
    }

def _validate(value: Mapping[str, Any]):
    errors = validate_judge_input(value)
    if errors:
        return None, _inconclusive(value, errors)
    return value, None

def _normalize(value: Mapping[str, Any]):
    evaluation_set = value["evaluation_set"]
    expected = set(evaluation_set["expected_event_ids"])
    labels = normalize_by_event_id(value["reviewed_labels"], "labels")
    baseline_matches = normalize_by_event_id(value["baseline"], "matches")
    candidate_matches = normalize_by_event_id(value["candidate"], "matches")
    errors = []

    if set(labels) != expected:
        missing = sorted(expected - set(labels))
        unexpected = sorted(set(labels) - expected)
        if missing:
            errors.append(f"reviewed labels missing event IDs: {missing}")
        if unexpected:
            errors.append(f"reviewed labels contain unexpected event IDs: {unexpected}")
    if not set(baseline_matches) <= expected or not set(candidate_matches) <= expected:
        errors.append("matches contain event IDs outside the evaluation inventory")
    if errors:
        return None, _inconclusive(value, errors)
    return (expected, labels, baseline_matches, candidate_matches), None


def _verify_compatibility(value: Mapping[str, Any]):
    baseline = value["baseline"]
    candidate = value["candidate"]
    provenance = value["provenance"]
    if baseline["execution"]["status"] != "completed" or candidate["execution"]["status"] != "completed":
        return ["baseline and candidate executions must both be completed"]
    if baseline["execution"]["execution_id"] != provenance["baseline_execution_id"]:
        return ["baseline execution provenance does not match artifact"]
    if candidate["execution"]["execution_id"] != provenance["candidate_execution_id"]:
        return ["candidate execution provenance does not match artifact"]
    if value["reviewed_labels"]["label_set_id"] != value["provenance"]["label_set_id"]:
        return ["label-set provenance does not match artifact"]
    criteria = value["criteria"]
    if (criteria["criteria_id"], criteria["criteria_version"]) != (
        value["provenance"]["criteria_id"], value["provenance"]["criteria_version"]
    ):
        return ["criteria provenance does not match criteria"]
    return []


def evaluate(value: Mapping[str, Any]):
    """Run validation, compatibility, comparison, metrics, and gates in order."""
    value, result = _validate(value)
    if result:
        return result
    normalized, result = _normalize(value)
    if result:
        return result
    expected, labels, baseline_matches, candidate_matches = normalized
    errors = _verify_compatibility(value)
    if errors:
        return _inconclusive(value, errors)

    comparison = compare_matches(baseline_matches, candidate_matches, labels)
    baseline_metrics = calculate_metrics(set(baseline_matches), labels, expected).as_dict()
    candidate_metrics = calculate_metrics(set(candidate_matches), labels, expected).as_dict()
    gates = evaluate_gates(comparison, baseline_metrics, value["criteria"]) + [
        {
            "gate_id": "evidence_completeness",
            "status": "passed",
            "reason": "All reviewed labels, match evidence, and required provenance were available.",
        },
        {
            "gate_id": "execution_validity",
            "status": "passed",
            "reason": "Baseline and candidate executions completed on the same evaluation set.",
        },
    ]
    reasons = ["All mandatory gates passed."]
    failed = [gate for gate in gates if gate["status"] == "failed"]
    status = "PASS" if not failed else "REJECT"
    if failed:
        reasons = [gate["reason"] for gate in failed]
    return build_report(value, baseline_metrics, candidate_metrics, comparison, gates, status, reasons)
