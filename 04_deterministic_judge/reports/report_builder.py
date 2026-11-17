from typing import Any, Mapping

def build_report(
    value: Mapping[str, Any],
    baseline_metrics: Mapping[str, Any],
    candidate_metrics: Mapping[str, Any],
    comparison: Any,
    gates: list[dict[str, Any]],
    status: str,
    reasons: list[str],
):
    evaluation_set = value["evaluation_set"]
    baseline = value["baseline"]
    candidate = value["candidate"]
    failed = [gate["gate_id"] for gate in gates if gate["status"] == "failed"]
    attack_count = baseline_metrics["true_positives"]
    retained = attack_count - len(comparison.lost_attack)
    retention = retained / attack_count if attack_count else 1.0
    return {
        "judge_input_id": value["judge_input_id"],
        "task_id": value["task_id"],
        "evaluation_summary": {
            "evaluation_set_id": evaluation_set["evaluation_set_id"],
            "evaluation_set_version": evaluation_set["evaluation_set_version"],
            "total_events": len(evaluation_set["expected_event_ids"]),
            "baseline_rule_version": baseline["rule"]["rule_version"],
            "candidate_rule_version": candidate["rule"]["rule_version"],
        },
        "baseline_metrics": dict(baseline_metrics),
        "candidate_metrics": dict(candidate_metrics),
        "comparison": {
            "retained_matches": comparison.retained,
            "removed_matches": comparison.removed,
            "added_matches": comparison.added,
            "lost_attack_matches": comparison.lost_attack,
            "removed_benign_matches": comparison.removed_benign,
            "new_attack_matches": comparison.new_attack,
            "new_benign_matches": comparison.new_benign,
            "false_positives_reduced": baseline_metrics["false_positives"] - candidate_metrics["false_positives"],
            "attack_detections_lost": len(comparison.lost_attack),
            "attack_retention": retention,
            "precision_change": candidate_metrics["precision"] - baseline_metrics["precision"],
            "recall_change": candidate_metrics["recall"] - baseline_metrics["recall"],
            "accuracy_change": candidate_metrics["accuracy"] - baseline_metrics["accuracy"],
            "f1_change": candidate_metrics["f1_score"] - baseline_metrics["f1_score"],
        },
        "mandatory_gates": gates,
        "decision": {"status": status, "reasons": reasons, "failed_gates": failed},
        "provenance": dict(value["provenance"]),
    }
