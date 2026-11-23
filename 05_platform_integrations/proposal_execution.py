"""Approval-gated platform operations for red and blue proposals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
from uuid import uuid4

from evidence_store.store import EvidenceStore
from splunk_execution import ApprovedSearchRequest, SplunkClient
from validation.proposals import require_valid_contract
from validation.rule_compiler import BaseRule, compile_candidate_rule


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


class ProposalExecutionService:
    """Validate proposals and execute only their separately approved Splunk searches.

    Red workflow steps are scenario descriptions, not host commands. The
    supplied approved search retrieves measured telemetry from Splunk.
    """

    def __init__(self, splunk: SplunkClient, evidence_store: EvidenceStore) -> None:
        self._splunk = splunk
        self._evidence_store = evidence_store

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
        result = self._splunk.execute(approved_search)
        evidence = self._evidence_store.put(
            {
                "contract_version": "0.1.0",
                "evidence_id": str(uuid4()),
                "task_id": proposal["task_id"],
                "proposal_id": proposal["proposal_id"],
                "detection_id": proposal["detection_under_test"]["detection_id"],
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
        reference = {
            "evidence_id": evidence["evidence_id"],
            "evidence_type": "telemetry",
            "provenance_ref": f"evidence_store:{evidence['evidence_id']}",
        }
        return RedProposalExecution(evidence, reference)

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
        result = self._splunk.execute(approved_search)
        candidate["validation"]["checks"].append("permissions")
        require_valid_contract(candidate, "candidate_rule")
        evidence = self._evidence_store.put(
            {
                "contract_version": "0.1.0",
                "evidence_id": str(uuid4()),
                "task_id": proposal["task_id"],
                "proposal_id": proposal["proposal_id"],
                "detection_id": proposal["detection_under_test"]["detection_id"],
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
        match_set = {
            "contract_version": "0.1.0",
            "match_set_id": str(uuid4()),
            "task_id": proposal["task_id"],
            "role": "candidate",
            "detection_id": candidate["detection_id"],
            "rule_version": candidate["candidate_rule_version"],
            "candidate_ref": candidate["candidate_id"],
            "dataset": dict(dataset),
            "execution": {
                "execution_id": result.execution.execution_id,
                "status": "partial" if result.execution.truncated else "completed",
                "search_ref": result.execution.operation_id,
                "started_at": result.execution.started_at,
                "finished_at": result.execution.completed_at,
            },
            "matches": [
                {
                    "event_id": event.event_id,
                    **({"sourcetype": event.sourcetype} if event.sourcetype else {}),
                    "event_time": event.timestamp,
                }
                for event in result.search_result.events
            ],
            "evidence_reference": {
                "evidence_id": evidence["evidence_id"],
                "evidence_type": "splunk_result",
                "provenance_ref": f"evidence_store:{evidence['evidence_id']}",
            },
        }
        require_valid_contract(match_set, "match_set")
        return BlueProposalExecution(candidate, match_set)
