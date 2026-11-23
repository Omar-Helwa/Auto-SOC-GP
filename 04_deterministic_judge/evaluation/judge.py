from typing import Any, Mapping
from match_sets.match_processing import compare_matches, normalize_by_event_id
from metrics.metrics import calculate_metrics
from reports.report_builder import build_report
from .mandatory_gates import evaluate_gates

def evaluate(value: Mapping[str, Any], failures: list[dict[str, str]]):
    """Compare, measure, and gate a bundle that has already been validated.
    ``failures`` is the output of validate_judge_input; any failure means INCONCLUSIVE.
    """
    if failures:
        return _inconclusive(value, failures)

    labels = normalize_by_event_id(value["reviewed_label_set"]["labels"])
    baseline_matches = normalize_by_event_id(value["baseline_match_set"]["matches"])
    candidate_matches = normalize_by_event_id(value["candidate_match_set"]["matches"])
    # The reviewed label set covers the whole frozen evaluation set (X-6, LS-2).
    event_ids = set(labels)

    comparison = compare_matches(baseline_matches, candidate_matches, labels)
    baseline_metrics = calculate_metrics(set(baseline_matches), labels, event_ids).as_dict()
    candidate_metrics = calculate_metrics(set(candidate_matches), labels, event_ids).as_dict()

    gates = evaluate_gates(comparison, baseline_metrics, value["criteria"]) + [
        {
            "gate_id": "evidence_completeness",
            "status": "passed",
            "reason": "Label coverage is complete, every label is reviewed, and every match is labelled.",
        },
        {
            "gate_id": "execution_validity",
            "status": "passed",
            "reason": "Baseline and candidate executions completed on the same frozen evaluation set.",
        },
    ]
    failed = [gate for gate in gates if gate["status"] == "failed"]
    status = "REJECT" if failed else "PASS"
    reasons = [gate["reason"] for gate in failed] if failed else ["All mandatory gates passed."]
    report = build_report(value, baseline_metrics, candidate_metrics, comparison, gates, status, reasons)
    return report

def _safe_get(value: Any, *path: str):
    for key in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value

def _inconclusive(value: Any, failures: list[dict[str, str]]):
    task_id = _safe_get(value, "task_id")
    return {
        "judge_input_id": _safe_get(value, "judge_input_id") if isinstance(_safe_get(value, "judge_input_id"), str) else None,
        "task_id": task_id if isinstance(task_id, str) else None,
        "decision": {
            "status": "INCONCLUSIVE",
            "reasons": [failure["message"] for failure in failures],
            "failed_gates": [],
            "failures": failures,
        },
    }

