"""Approval-gated platform operations for red and blue proposals."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping
from uuid import uuid4

from evidence_store.store import EvidenceStore
from splunk_execution import (
    ApprovedSearchRequest,
    SplunkClient,
    SplunkExecutionResult,
    TelemetryEvidence,
)
from validation.proposals import require_valid_contract
from validation.rule_compiler import BaseRule, compile_candidate_rule, render_base_rule


_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)


@dataclass(frozen=True)
class RedProposalExecution:
    telemetry_evidence: Mapping[str, Any]
    evidence_reference: Mapping[str, str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "telemetry_evidence": dict(self.telemetry_evidence),
            "evidence_reference": dict(self.evidence_reference),
        }


@dataclass(frozen=True)
class BlueProposalExecution:
    candidate_rule: Mapping[str, Any]
    match_set: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "candidate_rule": dict(self.candidate_rule),
            "match_set": dict(self.match_set),
        }


@dataclass(frozen=True)
class BaselineExecution:
    match_set: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"match_set": dict(self.match_set)}


class ProposalExecutionService:
    """Validate proposals and execute only their separately approved Splunk searches.

    Red workflow steps are scenario descriptions, not host commands. The
    supplied approved search retrieves measured telemetry from Splunk.
    """

    def __init__(
        self,
        splunk: SplunkClient,
        evidence_store: EvidenceStore,
        *,
        event_normalizer: Callable[[TelemetryEvidence], TelemetryEvidence] | None = None,
    ) -> None:
        # ``event_normalizer`` (for example
        # validation.events.normalize_frozen_set_event) is applied to every
        # returned event before it is stored or used as a match.
        self._splunk = splunk
        self._evidence_store = evidence_store
        self._normalize = event_normalizer

    def run_red_proposal(
        self,
        proposal: Mapping[str, Any],
        approved_search: ApprovedSearchRequest,
    ) -> RedProposalExecution:
        require_valid_contract(proposal, "red_proposal")
        if approved_search.task_id != proposal["task_id"]:
            raise ValueError("approved search task_id does not match the red proposal")
        if approved_search.proposal_id != proposal["proposal_id"]:
            raise ValueError("approved search proposal_id does not match the red proposal")
        result = self._normalized(self._splunk.execute(approved_search))
        evidence = self._store_evidence(
            result,
            task_id=proposal["task_id"],
            proposal_id=proposal["proposal_id"],
            detection_id=proposal["detection_under_test"]["detection_id"],
        )
        reference = {
            "evidence_id": evidence["evidence_id"],
            "evidence_type": "telemetry",
            "provenance_ref": f"evidence_store:{evidence['evidence_id']}",
        }
        return RedProposalExecution(evidence, reference)

    def run_baseline_rule(
        self,
        base_rule: BaseRule,
        *,
        proposal_id: str,
        approved_search: ApprovedSearchRequest,
        dataset: Mapping[str, Any],
    ) -> BaselineExecution:
        """Execute the unedited base rule on the frozen set and return a baseline match set.

        ``proposal_id`` is the proposal whose round requested the measurement;
        the approval must name the same proposal and dataset, and its SPL must
        equal the compiler's rendering of ``base_rule``.
        """
        if approved_search.task_id != base_rule.task_id:
            raise ValueError("approved search task_id does not match the base rule")
        if approved_search.proposal_id != proposal_id:
            raise ValueError("approved search proposal_id does not match the round proposal")
        if approved_search.spl.strip() != render_base_rule(base_rule):
            raise ValueError("approved search SPL does not exactly match the rendered base rule")
        if approved_search.dataset is None or dict(approved_search.dataset) != dict(dataset):
            raise ValueError("approved search dataset does not match the frozen evaluation set")
        result = self._normalized(self._splunk.execute(approved_search))
        evidence = self._store_evidence(
            result,
            task_id=base_rule.task_id,
            proposal_id=proposal_id,
            detection_id=base_rule.detection_id,
        )
        match_set = _match_set(
            result,
            evidence,
            task_id=base_rule.task_id,
            role="baseline",
            detection_id=base_rule.detection_id,
            rule_version=base_rule.rule_version,
            dataset=dataset,
        )
        require_valid_contract(match_set, "match_set")
        return BaselineExecution(match_set)

    def run_blue_proposal(
        self,
        proposal: Mapping[str, Any],
        base_rule: BaseRule,
        *,
        candidate_rule_version: str,
        approved_search: ApprovedSearchRequest,
        dataset: Mapping[str, Any],
    ) -> BlueProposalExecution:
        candidate = compile_candidate_rule(
            proposal, base_rule, candidate_rule_version=candidate_rule_version
        )
        if approved_search.task_id != proposal["task_id"]:
            raise ValueError("approved search task_id does not match the blue proposal")
        if approved_search.proposal_id != proposal["proposal_id"]:
            raise ValueError("approved search proposal_id does not match the blue proposal")
        if approved_search.spl.strip() != candidate["compiled_rule"]["text"]:
            raise ValueError("approved search SPL does not exactly match the compiled candidate rule")
        if approved_search.dataset is None or dict(approved_search.dataset) != dict(dataset):
            raise ValueError("approved search dataset does not match the frozen evaluation set")
        result = self._normalized(self._splunk.execute(approved_search))
        candidate["validation"]["checks"].append("permissions")
        require_valid_contract(candidate, "candidate_rule")
        evidence = self._store_evidence(
            result,
            task_id=proposal["task_id"],
            proposal_id=proposal["proposal_id"],
            detection_id=proposal["detection_under_test"]["detection_id"],
        )
        match_set = _match_set(
            result,
            evidence,
            task_id=proposal["task_id"],
            role="candidate",
            detection_id=candidate["detection_id"],
            rule_version=candidate["candidate_rule_version"],
            dataset=dataset,
            candidate_ref=candidate["candidate_id"],
        )
        require_valid_contract(match_set, "match_set")
        return BlueProposalExecution(candidate, match_set)

    def _normalized(self, result: SplunkExecutionResult) -> SplunkExecutionResult:
        if self._normalize is None:
            return result
        events = tuple(self._normalize(event) for event in result.search_result.events)
        return replace(result, search_result=replace(result.search_result, events=events))

    def _store_evidence(
        self,
        result: SplunkExecutionResult,
        *,
        task_id: str,
        proposal_id: str,
        detection_id: str,
    ) -> dict[str, Any]:
        evidence = self._evidence_store.put(
            {
                "contract_version": "0.1.0",
                "evidence_id": str(uuid4()),
                "task_id": task_id,
                "proposal_id": proposal_id,
                "detection_id": detection_id,
                "source": "splunk",
                "execution": {
                    "execution_id": result.execution.execution_id,
                    "status": result.execution.status,
                    "operation_id": result.execution.operation_id,
                    "approval_id": result.execution.approval_id,
                    "started_at": result.execution.started_at,
                    "completed_at": result.execution.completed_at,
                    "event_count": result.execution.event_count,
                    "truncated": result.execution.truncated,
                },
                "events": [event.as_dict() for event in result.search_result.events],
            }
        )
        require_valid_contract(evidence, "telemetry_evidence")
        return evidence


def _match_set(
    result: SplunkExecutionResult,
    evidence: Mapping[str, Any],
    *,
    task_id: str,
    role: str,
    detection_id: str,
    rule_version: str,
    dataset: Mapping[str, Any],
    candidate_ref: str | None = None,
) -> dict[str, Any]:
    match_set: dict[str, Any] = {
        "contract_version": "0.1.0",
        "match_set_id": str(uuid4()),
        "task_id": task_id,
        "role": role,
        "detection_id": detection_id,
        "rule_version": rule_version,
    }
    if candidate_ref is not None:
        match_set["candidate_ref"] = candidate_ref
    match_set.update(
        {
            "dataset": dict(dataset),
            "execution": {
                "execution_id": result.execution.execution_id,
                "status": "partial" if result.execution.truncated else "completed",
                "search_ref": result.execution.operation_id,
                "started_at": result.execution.started_at,
                "finished_at": result.execution.completed_at,
            },
            # event_time is optional metadata; matches join on event_id. A
            # timestamp that is not RFC 3339 is omitted here and kept
            # verbatim in the stored evidence.
            "matches": [
                {
                    "event_id": event.event_id,
                    **({"sourcetype": event.sourcetype} if event.sourcetype else {}),
                    **({"event_time": event.timestamp} if _RFC3339.fullmatch(event.timestamp) else {}),
                }
                for event in result.search_result.events
            ],
            "evidence_reference": {
                "evidence_id": evidence["evidence_id"],
                "evidence_type": "splunk_result",
                "provenance_ref": f"evidence_store:{evidence['evidence_id']}",
            },
        }
    )
    return match_set
