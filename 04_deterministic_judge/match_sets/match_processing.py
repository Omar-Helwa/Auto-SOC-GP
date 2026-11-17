from dataclasses import dataclass
from typing import Any, Mapping

@dataclass(frozen=True)
class Comparison:
    retained: list[str]
    removed: list[str]
    added: list[str]
    lost_attack: list[str]
    removed_benign: list[str]
    new_attack: list[str]
    new_benign: list[str]

def normalize_by_event_id( artifact: Mapping[str, Any], collection_name: str,):
    """Index an artifact collection by the provisional event_id identity."""
    return {
        item["event_id"]: item for item in artifact[collection_name]
    }

def compare_matches(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    labels: Mapping[str, Mapping[str, Any]],
):
    baseline_ids = set(baseline)
    candidate_ids = set(candidate)
    retained = sorted(baseline_ids & candidate_ids)
    removed = sorted(baseline_ids - candidate_ids)
    added = sorted(candidate_ids - baseline_ids)
    lost_attack = [event_id for event_id in removed if labels[event_id]["label"] == "attack"]
    removed_benign = [event_id for event_id in removed if labels[event_id]["label"] == "benign"]
    new_attack = [event_id for event_id in added if labels[event_id]["label"] == "attack"]
    new_benign = [event_id for event_id in added if labels[event_id]["label"] == "benign"]
    return Comparison(retained, removed, added, lost_attack, removed_benign, new_attack, new_benign)
