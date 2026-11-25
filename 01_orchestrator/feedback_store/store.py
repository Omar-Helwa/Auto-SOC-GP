"""Query feedback records and their linked artifacts without duplicating writes."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from orchestrator_interfaces.artifacts import ContractArtifactStore
from orchestrator_interfaces.validation import InterfaceValidator


class FeedbackStoreError(RuntimeError):
    """Feedback could not be saved, queried, or resolved consistently."""


class DuplicateFeedbackError(FeedbackStoreError):
    """A task already has a different feedback record."""


@dataclass(frozen=True)
class FeedbackBundle:
    """Feedback contract plus the role-specific messages it points to.

    ``retrieval_eligible`` is a conservative read-time hint. It is true only
    for a canonical PASS decision; the shared feedback contract is not changed.
    """

    feedback_record: Mapping[str, Any]
    artifact_payloads: Mapping[str, Mapping[str, Any]]
    retrieval_eligible: bool


_ARTIFACT_CONTRACTS = {
    "red_proposal": "red_proposal",
    "telemetry_evidence": "telemetry_evidence",
    "reviewed_label_set": "reviewed_label_set",
    "blue_proposal": "blue_proposal",
    "candidate_rule": "candidate_rule",
    "baseline_match_set": "match_set",
    "candidate_match_set": "match_set",
    "judge_result": "judge_result",
}


class FeedbackStore:
    """Feedback persistence/query facade over the existing artifact store.

    It writes the shared ``feedback_record`` once through ``artifacts.save``.
    Queries resolve that same document and its referenced artifacts; no second
    feedback collection or copied feedback document is created here.
    """

    def __init__(self, artifacts: ContractArtifactStore, validator: Optional[Any] = None):
        self.artifacts = artifacts
        self.validator = validator or InterfaceValidator()

    def save(self, feedback_record: Mapping[str, Any]) -> str:
        document = self.validator.validate("feedback_record", feedback_record)
        task_id = document["task_id"]
        if document["round_id"] != task_id:
            raise FeedbackStoreError("feedback_record.round_id must equal task_id")

        existing = self._find_records(task_id)
        if existing:
            if all(_same_feedback(stored, document) for _, stored in existing):
                return existing[0][0]
            raise DuplicateFeedbackError(f"Task {task_id!r} has conflicting feedback records")
        return self.artifacts.save("feedback_record", document)

    def get_by_task(self, task_id: str) -> Optional[dict[str, Any]]:
        """Return the saved shared feedback contract for a round/task id."""
        rows = self._find_records(task_id)
        if not rows:
            return None
        if len(rows) != 1:
            raise DuplicateFeedbackError(f"Task {task_id!r} has {len(rows)} feedback records")
        return copy.deepcopy(rows[0][1])

    def list_for_task(self, task_id: str) -> list[dict[str, Any]]:
        """List matching feedback records (normally zero or one)."""
        return [copy.deepcopy(document) for _, document in self._find_records(task_id)]

    def get_bundle(self, task_id: str) -> Optional[FeedbackBundle]:
        """Resolve feedback and all referenced role/evaluation artifacts."""
        rows = self._find_records(task_id)
        if not rows:
            return None
        if len(rows) != 1:
            raise DuplicateFeedbackError(f"Task {task_id!r} has {len(rows)} feedback records")
        _reference, feedback = rows[0]
        payloads: dict[str, Mapping[str, Any]] = {}
        for artifact_name, contract in _ARTIFACT_CONTRACTS.items():
            reference = feedback["artifact_refs"].get(artifact_name)
            if not reference:
                raise FeedbackStoreError(f"Feedback for {task_id!r} is missing reference {artifact_name!r}")
            try:
                payloads[artifact_name] = self.artifacts.load(contract, reference)
            except Exception as exc:
                raise FeedbackStoreError(
                    f"Could not resolve {artifact_name!r} for feedback task {task_id!r}"
                ) from exc

        status = feedback["decision"]["status"]
        return FeedbackBundle(
            feedback_record=copy.deepcopy(feedback),
            artifact_payloads=payloads,
            retrieval_eligible=status == "PASS",
        )

    def _find_records(self, task_id: str) -> list[tuple[str, dict[str, Any]]]:
        if not isinstance(task_id, str) or not task_id.strip():
            raise FeedbackStoreError("task_id must be a non-empty string")
        finder = getattr(self.artifacts, "find_by_task", None)
        if not callable(finder):
            raise FeedbackStoreError("Artifact store must support find_by_task for feedback queries")
        rows = finder("feedback_record", task_id)
        validated = []
        for reference, document in rows:
            payload = self.validator.validate("feedback_record", document)
            if payload["task_id"] != task_id or payload["round_id"] != task_id:
                raise FeedbackStoreError("Stored feedback task/round id does not match its query")
            validated.append((reference, payload))
        return validated


def _same_feedback(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    """Ignore only assembly time so retrying completion reuses the same record."""
    left_copy, right_copy = dict(left), dict(right)
    left_copy.pop("recorded_at", None)
    right_copy.pop("recorded_at", None)
    return json.dumps(left_copy, sort_keys=True, allow_nan=False) == json.dumps(
        right_copy, sort_keys=True, allow_nan=False
    )
