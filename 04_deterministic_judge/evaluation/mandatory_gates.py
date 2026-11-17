from typing import Any, Mapping

def evaluate_gates(
    comparison: Any,
    baseline_metrics: Mapping[str, Any],
    criteria: Mapping[str, Any],
):
    required_attacks = baseline_metrics["true_positives"]
    retained_attacks = required_attacks - len(comparison.lost_attack)
    retention = retained_attacks / required_attacks if required_attacks else 1.0
    retention_passed = retention >= criteria["minimum_attack_retention"]
    benign_count = len(comparison.new_benign)
    benign_passed = benign_count <= criteria["maximum_new_benign_matches"]
    return [
        {
            "gate_id": "attack_retention",
            "status": "passed" if retention_passed else "failed",
            "expected": criteria["minimum_attack_retention"],
            "actual": retention,
            "reason": "All required attack detections were retained." if retention_passed
            else "The candidate lost more attack detections than allowed.",
        },
        {
            "gate_id": "new_benign_matches",
            "status": "passed" if benign_passed else "failed",
            "expected_maximum": criteria["maximum_new_benign_matches"],
            "actual": benign_count,
            "reason": "No excessive new benign matches were introduced." if benign_passed
            else "The candidate introduced too many benign matches.",
        },
    ]
