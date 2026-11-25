"""Cross-message rules that must pass before the Judge receives an input."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from ..validation import InterfaceError


class InvalidCrossContract(InterfaceError):
    """The messages contradict the frozen round or each other."""


class IncompleteEvidenceError(InterfaceError):
    """The data is well-formed but cannot support a deterministic decision."""


class ContractAlignmentError(InterfaceError):
    """Owned interface contracts do not currently agree on a representation."""


def _dataset_identity(document: Mapping[str, Any]) -> Mapping[str, Any]:
    return document.get("dataset", {})


def validate_judge_evidence(
    config,
    blue_proposal: Mapping[str, Any],
    candidate_rule: Mapping[str, Any],
    baseline_match_set: Mapping[str, Any],
    candidate_match_set: Mapping[str, Any],
    reviewed_label_set: Mapping[str, Any],
) -> None:
    """Apply the shared validation_rules that JSON Schema cannot express."""
    task_id = config.task_id
    detection_id = config.detection["detection_id"]

    for label, document in (
        ("blue_proposal", blue_proposal),
        ("candidate_rule", candidate_rule),
        ("baseline_match_set", baseline_match_set),
        ("candidate_match_set", candidate_match_set),
    ):
        if document.get("task_id") != task_id:
            raise InvalidCrossContract(f"{label}.task_id does not match round {task_id!r}")

    if baseline_match_set.get("role") != "baseline":
        raise InvalidCrossContract("baseline match_set must have role 'baseline'")
    if candidate_match_set.get("role") != "candidate":
        raise InvalidCrossContract("candidate match_set must have role 'candidate'")

    if blue_proposal.get("detection_under_test", {}).get("detection_id") != detection_id:
        raise InvalidCrossContract("blue_proposal targets a different detection")
    if blue_proposal.get("detection_under_test", {}).get("rule_version") != config.detection["rule_version"]:
        raise InvalidCrossContract("blue_proposal targets a different baseline rule version")
    if candidate_rule.get("detection_id") != detection_id:
        raise InvalidCrossContract("candidate_rule targets a different detection")
    if candidate_rule.get("proposal_id") != blue_proposal.get("proposal_id"):
        raise InvalidCrossContract("candidate_rule was not built from the stored blue_proposal")

    if baseline_match_set.get("rule_version") != config.detection["rule_version"]:
        raise InvalidCrossContract("baseline match_set rule_version differs from the frozen round request")
    if candidate_rule.get("base_rule_version") != baseline_match_set.get("rule_version"):
        raise InvalidCrossContract("candidate_rule.base_rule_version differs from the baseline match_set")
    if candidate_rule.get("candidate_rule_version") != candidate_match_set.get("rule_version"):
        raise InvalidCrossContract("candidate rule version differs from candidate match_set.rule_version")
    if candidate_match_set.get("candidate_ref") != candidate_rule.get("candidate_id"):
        raise InvalidCrossContract("candidate match_set.candidate_ref does not identify the candidate_rule")

    compiled = candidate_rule.get("compiled_rule", {})
    expected_hash = hashlib.sha256(compiled.get("text", "").encode("utf-8")).hexdigest()
    if compiled.get("sha256", "").lower() != expected_hash:
        raise InvalidCrossContract("candidate_rule compiled_rule.sha256 does not match compiled_rule.text")

    expected_dataset = {
        name: config.dataset[name]
        for name in ("dataset_id", "dataset_version", "evaluation_set_id", "evaluation_set_checksum")
        if name in config.dataset
    }
    datasets = {
        "baseline_match_set": _dataset_identity(baseline_match_set),
        "candidate_match_set": _dataset_identity(candidate_match_set),
        "reviewed_label_set": _dataset_identity(reviewed_label_set),
    }
    for label, dataset in datasets.items():
        for name, expected in expected_dataset.items():
            if dataset.get(name) != expected:
                raise IncompleteEvidenceError(
                    f"{label} dataset field {name!r} differs from the frozen round request",
                    {"contract": label, "field": name},
                )
    identity_fields = ("dataset_id", "dataset_version", "evaluation_set_id", "evaluation_set_checksum")
    for name in identity_fields:
        observed = [dataset.get(name) for dataset in datasets.values() if name in dataset]
        if observed and (len(observed) != len(datasets) or len(set(observed)) != 1):
            raise IncompleteEvidenceError(
                f"match sets and reviewed labels do not agree on dataset.{name}",
                {"field": name},
            )

    for label, match_set in (("baseline", baseline_match_set), ("candidate", candidate_match_set)):
        if match_set.get("detection_id") != detection_id:
            raise IncompleteEvidenceError(f"{label} match_set detection_id differs from the round")
        event_ids = [item.get("event_id") for item in match_set.get("matches", [])]
        if len(event_ids) != len(set(event_ids)):
            raise InvalidCrossContract(f"{label} match_set contains duplicate event_id values")
        if match_set.get("execution", {}).get("status") != "completed":
            raise IncompleteEvidenceError(f"{label} match_set execution did not complete")

    labels = reviewed_label_set.get("labels", [])
    label_ids = [item.get("event_id") for item in labels]
    if len(label_ids) != len(set(label_ids)):
        raise InvalidCrossContract("reviewed_label_set contains duplicate event_id values")
    total_events = reviewed_label_set.get("coverage", {}).get("total_events")
    if total_events is not None and len(labels) > total_events:
        raise InvalidCrossContract("reviewed_label_set has more labels than coverage.total_events")
    if reviewed_label_set.get("coverage", {}).get("complete") is True and len(labels) != total_events:
        raise InvalidCrossContract("complete reviewed_label_set does not cover total_events")
    if reviewed_label_set.get("coverage", {}).get("complete") is not True:
        raise IncompleteEvidenceError("reviewed_label_set coverage is incomplete")
    if any(item.get("review", {}).get("status") != "reviewed" for item in labels):
        raise IncompleteEvidenceError("reviewed_label_set contains disputed or unreviewed labels")

    labeled_ids = set(label_ids)
    matched_ids = {
        item["event_id"]
        for match_set in (baseline_match_set, candidate_match_set)
        for item in match_set.get("matches", [])
    }
    missing = sorted(matched_ids - labeled_ids)
    if missing:
        raise IncompleteEvidenceError(
            "one or more matched events have no reviewed label",
            {"missing_event_ids": missing},
        )
