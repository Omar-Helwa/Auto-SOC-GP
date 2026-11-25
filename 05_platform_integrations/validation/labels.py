"""Readiness checks for frozen, human-reviewed evaluation label sets.

The Platform never promotes labels: these checks only read a prepared
``reviewed_label_set`` and refuse it unless a human review already marked it
complete. The evaluation-set checksum convention matches the dataset builders
in ``labelled_data/public_datasets/scripts``: SHA-256 over the sorted event
IDs joined by newlines.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

from .proposals import ContractValidationError, require_valid_contract

DATASET_FIELDS = (
    "dataset_id",
    "dataset_version",
    "evaluation_set_id",
    "evaluation_set_checksum",
)
_EVALUATION_SET_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class LabelSetNotReady(ValueError):
    """The label set cannot be used as ground truth for this round."""


def evaluation_set_checksum(event_ids: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(sorted(event_ids)).encode("utf-8")).hexdigest()


def require_frozen_dataset(dataset: Any) -> dict[str, str]:
    """Return the round dataset reference, requiring every identity field."""
    if not isinstance(dataset, Mapping):
        raise LabelSetNotReady("round dataset must be an object")
    missing = [name for name in DATASET_FIELDS if not dataset.get(name)]
    if missing:
        raise LabelSetNotReady(
            f"round dataset is missing frozen identity field(s): {missing}; "
            "the evaluation_set_checksum is required to verify event coverage"
        )
    if not _EVALUATION_SET_ID.fullmatch(str(dataset["evaluation_set_id"])):
        raise LabelSetNotReady(
            "evaluation_set_id must contain only letters, digits, '.', '_' or '-'"
        )
    if not re.fullmatch(r"[A-Fa-f0-9]{64}", str(dataset["evaluation_set_checksum"])):
        raise LabelSetNotReady("evaluation_set_checksum must be a 64-character SHA-256")
    return {name: dataset[name] for name in DATASET_FIELDS}


def load_prepared_label_set(prepared_root: str | Path, evaluation_set_id: str) -> dict[str, Any]:
    """Read ``<prepared_root>/<evaluation_set_id>/labels/reviewed_label_set.json``."""
    if not isinstance(evaluation_set_id, str) or not _EVALUATION_SET_ID.fullmatch(evaluation_set_id):
        raise LabelSetNotReady("evaluation_set_id is not a safe directory name")
    path = Path(prepared_root) / evaluation_set_id / "labels" / "reviewed_label_set.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LabelSetNotReady(f"reviewed label set not found: {path}") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LabelSetNotReady(f"reviewed label set is unreadable or malformed: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise LabelSetNotReady(f"reviewed label set is not a JSON object: {path}")
    return value


def require_judge_ready_label_set(
    label_set: Any, dataset: Mapping[str, Any]
) -> dict[str, Any]:
    """Return ``label_set`` unchanged if it is complete, reviewed, and frozen to ``dataset``.

    Raises ``LabelSetNotReady`` with every blocking reason. Nothing is
    modified: unreviewed or incomplete sets must be reviewed by a human and
    rebuilt, not repaired here.
    """
    expected = require_frozen_dataset(dataset)
    try:
        require_valid_contract(label_set, "reviewed_label_set")
    except ContractValidationError as exc:
        raise LabelSetNotReady(f"reviewed label set is malformed: {exc}") from exc

    name = label_set["label_set_id"]
    problems: list[str] = []
    observed_dataset = label_set["dataset"]
    for field in DATASET_FIELDS:
        if observed_dataset.get(field) != expected[field]:
            problems.append(
                f"dataset.{field}={observed_dataset.get(field)!r} differs from the frozen round "
                f"value {expected[field]!r}"
            )

    labels = label_set["labels"]
    ids = [label["event_id"] for label in labels]
    duplicates = sorted(event_id for event_id, count in Counter(ids).items() if count > 1)
    if duplicates:
        problems.append(f"duplicate label event_id values (LS-1): {duplicates[:5]}")
    coverage = label_set["coverage"]
    if len(labels) > coverage["total_events"]:
        problems.append("more labels than coverage.total_events (LS-3)")
    if coverage["complete"] is not True:
        problems.append("coverage.complete is false")
    elif len(labels) != coverage["total_events"]:
        problems.append("coverage.complete is true but labels do not cover total_events (LS-2)")
    if not labels:
        problems.append("the label set is empty")

    statuses = Counter(label["review"]["status"] for label in labels)
    not_reviewed = len(labels) - statuses.get("reviewed", 0)
    if not_reviewed:
        problems.append(
            f"{not_reviewed} of {len(labels)} labels are not reviewed "
            f"({dict(sorted(statuses.items()))})"
        )
    unattributed = sum(
        1
        for label in labels
        if label["review"]["status"] == "reviewed" and not label["review"].get("reviewer")
    )
    if unattributed:
        problems.append(f"{unattributed} reviewed labels have no reviewer attribution")

    if not duplicates and ids and evaluation_set_checksum(ids) != expected["evaluation_set_checksum"]:
        problems.append("label event IDs do not hash to the frozen evaluation_set_checksum")

    if problems:
        raise LabelSetNotReady(
            f"label set {name!r} is not judge-ready: " + "; ".join(problems)
        )
    return label_set


def label_sources(label_set: Mapping[str, Any]) -> set[str]:
    return {label.get("source") for label in label_set.get("labels", [])}
