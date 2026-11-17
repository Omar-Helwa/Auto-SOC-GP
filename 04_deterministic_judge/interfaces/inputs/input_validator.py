from typing import Any, Mapping

def _required(mapping: Mapping[str, Any], name: str, errors: list[str], path: str):
    if name not in mapping:
        errors.append(f"{path}.{name} is required")
        return None
    return mapping[name]

def validate_judge_input(value: Mapping[str, Any]):
    """Return all validation errors without attempting evaluation."""
    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ["judge input must be an object"]

    for name in ("judge_input_id", "task_id", "evaluation_set", "baseline", "candidate",
                 "reviewed_labels", "criteria", "provenance"):
        _required(value, name, errors, "input")

    evaluation_set = value.get("evaluation_set")
    if isinstance(evaluation_set, Mapping):
        for name in ("evaluation_set_id", "evaluation_set_version", "expected_event_ids"):
            _required(evaluation_set, name, errors, "evaluation_set")
        expected = evaluation_set.get("expected_event_ids")
        if not isinstance(expected, list) or not expected or any(
            not isinstance(item, str) or not item for item in expected
        ):
            errors.append("evaluation_set.expected_event_ids must be a non-empty list of strings")
        elif len(set(expected)) != len(expected):
            errors.append("evaluation_set.expected_event_ids contains duplicates")

    for side in ("baseline", "candidate"):
        artifact = value.get(side)
        if not isinstance(artifact, Mapping):
            errors.append(f"{side} must be an object")
            continue
        for name in ("task_id", "evaluation_set_id", "evaluation_set_version", "execution", "rule", "matches"):
            _required(artifact, name, errors, side)
        execution = artifact.get("execution")
        if isinstance(execution, Mapping):
            for name in ("execution_id", "status"):
                _required(execution, name, errors, f"{side}.execution")
        rule = artifact.get("rule")
        if isinstance(rule, Mapping):
            for name in ("rule_id", "rule_version"):
                _required(rule, name, errors, f"{side}.rule")
        matches = artifact.get("matches")
        if not isinstance(matches, list):
            errors.append(f"{side}.matches must be a list")
        else:
            identities = []
            for index, match in enumerate(matches):
                if not isinstance(match, Mapping):
                    errors.append(f"{side}.matches[{index}] must be an object")
                    continue
                event_id = match.get("event_id")
                if not isinstance(event_id, str) or not event_id:
                    errors.append(f"{side}.matches[{index}].event_id must be a non-empty string")
                else:
                    identities.append(event_id)
                if not isinstance(match.get("evidence_ref"), str) or not match["evidence_ref"]:
                    errors.append(f"{side}.matches[{index}].evidence_ref is required")
            if len(set(identities)) != len(identities):
                errors.append(f"{side}.matches contains duplicate event_id identities")

    labels = value.get("reviewed_labels")
    if not isinstance(labels, Mapping):
        errors.append("reviewed_labels must be an object")
    else:
        for name in ("label_set_id", "evaluation_set_id", "evaluation_set_version", "labels"):
            _required(labels, name, errors, "reviewed_labels")
        label_items = labels.get("labels")
        if not isinstance(label_items, list):
            errors.append("reviewed_labels.labels must be a list")
        else:
            identities = []
            for index, item in enumerate(label_items):
                if not isinstance(item, Mapping):
                    errors.append(f"reviewed_labels.labels[{index}] must be an object")
                    continue
                event_id = item.get("event_id")
                label = item.get("label")
                if not isinstance(event_id, str) or not event_id:
                    errors.append(f"reviewed_labels.labels[{index}].event_id is required")
                else:
                    identities.append(event_id)
                if label not in ("attack", "benign"):
                    errors.append(f"reviewed_labels.labels[{index}].label must be attack or benign")
                if item.get("review_status") != "approved":
                    errors.append(f"reviewed_labels.labels[{index}] is not approved")
                if not isinstance(item.get("evidence_ref"), str) or not item["evidence_ref"]:
                    errors.append(f"reviewed_labels.labels[{index}].evidence_ref is required")
            if len(set(identities)) != len(identities):
                errors.append("reviewed_labels.labels contains duplicate event_id identities")

    criteria = value.get("criteria")
    if not isinstance(criteria, Mapping):
        errors.append("criteria must be an object")
    else:
        for name in ("criteria_id", "criteria_version", "minimum_attack_retention",
                     "maximum_new_benign_matches"):
            _required(criteria, name, errors, "criteria")
        for name in ("criteria_id", "criteria_version"):
            if not isinstance(criteria.get(name), str) or not criteria[name]:
                errors.append(f"criteria.{name} must be a non-empty string")
        retention = criteria.get("minimum_attack_retention")
        if not isinstance(retention, (int, float)) or isinstance(retention, bool) or not 0 <= retention <= 1:
            errors.append("criteria.minimum_attack_retention must be a number from 0 to 1")
        maximum = criteria.get("maximum_new_benign_matches")
        if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 0:
            errors.append("criteria.maximum_new_benign_matches must be a non-negative integer")

    provenance = value.get("provenance")
    if not isinstance(provenance, Mapping):
        errors.append("provenance must be an object")
    else:
        for name in ("baseline_execution_id", "candidate_execution_id", "label_set_id",
                     "criteria_id", "criteria_version"):
            _required(provenance, name, errors, "provenance")
        for name in ("baseline_execution_id", "candidate_execution_id", "label_set_id",
                     "criteria_id", "criteria_version"):
            if not isinstance(provenance.get(name), str) or not provenance[name]:
                errors.append(f"provenance.{name} must be a non-empty string")

    if isinstance(evaluation_set, Mapping) and isinstance(value.get("reviewed_labels"), Mapping):
        if evaluation_set.get("evaluation_set_id") != value["reviewed_labels"].get("evaluation_set_id"):
            errors.append("reviewed_labels evaluation-set identity is incompatible")
        if evaluation_set.get("evaluation_set_version") != value["reviewed_labels"].get("evaluation_set_version"):
            errors.append("reviewed_labels evaluation-set version is incompatible")
    if isinstance(evaluation_set, Mapping):
        for side in ("baseline", "candidate"):
            artifact = value.get(side)
            if isinstance(artifact, Mapping):
                if artifact.get("task_id") != value.get("task_id"):
                    errors.append(f"{side} task identity is incompatible")
                if artifact.get("evaluation_set_id") != evaluation_set.get("evaluation_set_id"):
                    errors.append(f"{side} evaluation-set identity is incompatible")
                if artifact.get("evaluation_set_version") != evaluation_set.get("evaluation_set_version"):
                    errors.append(f"{side} evaluation-set version is incompatible")

    return errors
