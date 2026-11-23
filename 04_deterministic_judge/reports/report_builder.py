from typing import Any, Mapping

def build_report( value: Mapping[str, Any], baseline_metrics: Mapping[str, Any], candidate_metrics: Mapping[str, Any],
                  comparison: Any, gates: list[dict[str, Any]], status: str, reasons: list[str],
):
    baseline = value["baseline_match_set"]
    candidate = value["candidate_match_set"]
    labels = value["reviewed_label_set"]
    criteria = value["criteria"]
    dataset = labels["dataset"]
    failed = [gate["gate_id"] for gate in gates if gate["status"] == "failed"]
    attack_count = baseline_metrics["true_positives"]
    retained = attack_count - len(comparison.lost_attack)
    retention = retained / attack_count if attack_count else 1.0
    return {
        "judge_input_id": value["judge_input_id"],
        "task_id": value["task_id"],
        "evaluation_summary": {
            "detection_id": value["detection_id"],
            "dataset_id": dataset["dataset_id"],
            "dataset_version": dataset["dataset_version"],
            "evaluation_set_id": dataset["evaluation_set_id"],
            "total_events": labels["coverage"]["total_events"],
            "baseline_rule_version": baseline["rule_version"],
            "candidate_rule_version": candidate["rule_version"],
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
        "decision": {"status": status, "reasons": reasons, "failed_gates": failed, "failures": []},
        "provenance": {
            "baseline_match_set_id": baseline["match_set_id"],
            "candidate_match_set_id": candidate["match_set_id"],
            "baseline_execution_id": baseline["execution"]["execution_id"],
            "candidate_execution_id": candidate["execution"]["execution_id"],
            "candidate_ref": candidate["candidate_ref"],
            "label_set_id": labels["label_set_id"],
            "label_set_version": labels["label_set_version"],
            "criteria": {
                "minimum_attack_retention": criteria["minimum_attack_retention"],
                "maximum_new_benign_matches": criteria["maximum_new_benign_matches"],
            },
            "contract_versions": {
                "match_set": baseline["contract_version"],
                "reviewed_label_set": labels["contract_version"],
                "judge_input": value["contract_version"],
            },
            "versions": dict(value["versions"]),
        },
    }
