from dataclasses import asdict, dataclass
from typing import Any, Mapping

@dataclass(frozen=True)
class Metrics:
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    accuracy: float
    f1_score: float

    def as_dict(self):
        return asdict(self)

def ratio(numerator: int, denominator: int):
    return numerator / denominator if denominator else 0.0

def calculate_metrics(
    match_ids: set[str],
    labels: Mapping[str, Mapping[str, Any]],
    event_ids: set[str],
):
    attacks = {event_id for event_id in event_ids if labels[event_id]["label"] == "attack"}
    benign = event_ids - attacks
    true_positives = len(match_ids & attacks)
    false_positives = len(match_ids & benign)
    false_negatives = len(attacks - match_ids)
    true_negatives = len(benign - match_ids)
    precision = ratio(true_positives, true_positives + false_positives)
    recall = ratio(true_positives, true_positives + false_negatives)
    accuracy = ratio(true_positives + true_negatives, len(event_ids))
    f1_score = ratio(2 * precision * recall, precision + recall)
    return Metrics(true_positives, false_positives, true_negatives, false_negatives,
                   precision, recall, accuracy, f1_score)
