"""Build and persist outbound messages at the Orchestrator boundary."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from ..artifacts import ContractArtifactStore, save_once
from ..validation import InterfaceError, InterfaceValidator
from round_management.states import RoundState
from .cross_contract import (
    ContractAlignmentError,
    IncompleteEvidenceError,
    InvalidCrossContract,
    validate_judge_evidence,
)

_FEEDBACK_ARTIFACTS = (
    "red_proposal",
    "telemetry_evidence",
    "reviewed_label_set",
    "blue_proposal",
    "candidate_rule",
    "baseline_match_set",
    "candidate_match_set",
    "judge_result",
)


class OrchestratorOutputAdapter:
    """Build role inputs and feedback while keeping round state authoritative."""

    def __init__(self, manager, artifacts: ContractArtifactStore, validator: Optional[InterfaceValidator] = None):
        from feedback_store import FeedbackStore

        self.manager = manager
        self.artifacts = artifacts
        self.validator = validator or InterfaceValidator()
        self.feedback_store = FeedbackStore(artifacts, self.validator)
        self.audit_writer = None

    def build_red_input(self, round_id: str) -> dict:
        record = self.manager.get_round(round_id)
        message = record.config.to_red_input()
        message = self.validator.validate("red_input", message)
        red_ref = save_once(self.artifacts, "red_input", message)
        request_rows = self.artifacts.find_by_task("round_request", round_id)
        request_refs = {"round_request": request_rows[0][0]} if request_rows else {}
        self._audit_outbound_input(
            "red_role", RoundState.RED_PROPOSED, record, message,
            contract_name="red_input",
            input_artifact_refs=request_refs,
            output_artifact_refs={"red_input": red_ref},
        )
        return message

    def build_blue_input(
        self,
        round_id: str,
        evidence_view: Mapping[str, Any],
        edit_constraints: Mapping[str, Any],
        *,
        blue_detection: Optional[Mapping[str, Any]] = None,
        prior_blue_edits: Optional[list[Mapping[str, Any]]] = None,
    ) -> dict:
        """Assemble Blue's role input from verified cases and a trusted rule view.

        `blue_detection` must come from an approved rule representation
        adapter. The representation must be explicitly Sigma or Splunk SPL,
        and its detection identity/version must match the frozen request.
        """
        record = self.manager.get_round(round_id)
        config = record.config
        if not isinstance(evidence_view, Mapping):
            raise InterfaceError("Blue evidence projection must be a mapping")
        required_evidence = ("task_id", "detection_id", "false_positives", "must_detect")
        missing_evidence = [name for name in required_evidence if name not in evidence_view]
        if missing_evidence:
            raise InterfaceError(
                "Blue evidence projection is missing required values",
                {"missing": missing_evidence},
            )
        evidence = dict(evidence_view)
        if evidence["task_id"] != round_id or evidence["detection_id"] != config.detection["detection_id"]:
            raise InvalidCrossContract("Blue evidence view does not belong to this round and detection")

        source_rule = blue_detection
        if source_rule is None:
            source_rule = config.detection
        if source_rule.get("rule_format") not in {"sigma", "spl"}:
            raise ContractAlignmentError(
                "Blue input requires an explicitly supported rule_format ('sigma' or 'spl'). "
                "Provide an approved, version-matched rule representation; no implicit conversion is allowed."
            )
        if source_rule.get("detection_id") != config.detection["detection_id"] or source_rule.get("rule_version") != config.detection["rule_version"]:
            raise InvalidCrossContract("Blue rule representation does not match the frozen detection identity/version")

        detection = {
            key: source_rule[key]
            for key in ("detection_id", "rule_version", "rule_format", "rule_text", "logic_summary")
            if key in source_rule
        }
        if "attack_techniques" in source_rule:
            detection["attack_techniques"] = source_rule["attack_techniques"]
        message: dict[str, Any] = {
            "contract_version": "0.1.0",
            "task_id": round_id,
            "prompt_version": config.versions["blue_prompt"],
            "output_contract_version": "0.1.0",
            "detection": detection,
            "false_positives": evidence["false_positives"],
            "must_detect": evidence["must_detect"],
            "edit_constraints": dict(edit_constraints),
        }
        if prior_blue_edits is not None:
            message["prior_blue_edits"] = list(prior_blue_edits)
        message = self.validator.validate("blue_input", message)
        self._audit_outbound_input(
            "blue_role", RoundState.BLUE_PROPOSED, record, message,
            contract_name="blue_input",
            input_artifact_refs=dict(record.artifacts),
        )
        return message

    def build_judge_input(self, round_id: str) -> dict:
        record = self.manager.get_round(round_id)
        if record.state is not RoundState.CANDIDATE_EXECUTED:
            raise InterfaceError("Judge input can only be assembled after candidate execution")
        refs = record.artifacts
        needed = ("blue_proposal", "candidate_rule", "baseline_match_set", "candidate_match_set", "reviewed_label_set")
        missing = [name for name in needed if name not in refs]
        if missing:
            raise IncompleteEvidenceError("Judge input is missing required artifact references", {"missing": missing})

        blue = self._load("blue_proposal", refs["blue_proposal"])
        candidate_rule = self._load("candidate_rule", refs["candidate_rule"])
        baseline = self._load("match_set", refs["baseline_match_set"])
        candidate = self._load("match_set", refs["candidate_match_set"])
        labels = self._load("reviewed_label_set", refs["reviewed_label_set"])
        validate_judge_evidence(record.config, blue, candidate_rule, baseline, candidate, labels)

        # Preserve the shared match-set and reviewed-label contracts verbatim
        # inside the published JudgeInput bundle.
        frozen_request = record.config.to_dict()
        message = {
            "contract_version": "0.1.0",
            "judge_input_id": f"judge-input-{round_id}",
            "task_id": round_id,
            "detection_id": record.config.detection["detection_id"],
            "baseline_match_set": baseline,
            "candidate_match_set": candidate,
            "reviewed_label_set": labels,
            "criteria": frozen_request["criteria"]["thresholds"],
            "versions": record.config.pinned_versions(),
        }
        message = self.validator.validate("judge_input", message)
        self._audit_outbound_input(
            "deterministic_judge", RoundState.JUDGED, record, message,
            contract_name="judge_input",
            input_artifact_refs=dict(record.artifacts),
        )
        return message

    def build_feedback_record(self, round_id: str) -> dict:
        record = self.manager.get_round(round_id)
        if record.state is not RoundState.JUDGED:
            raise InterfaceError("Feedback can only be emitted after a judge_result has been recorded")
        missing = [name for name in _FEEDBACK_ARTIFACTS if name not in record.artifacts]
        if missing:
            raise IncompleteEvidenceError("Feedback record is missing audit artifact references", {"missing": missing})
        judge_result = self._load("judge_result", record.artifacts["judge_result"])
        message = {
            "contract_version": "0.1.0",
            "task_id": round_id,
            "round_id": round_id,
            "decision": judge_result["decision"],
            "artifact_refs": {name: record.artifacts[name] for name in _FEEDBACK_ARTIFACTS},
            "versions": record.config.pinned_versions(),
            "judge_result": judge_result,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        return self.validator.validate("feedback_record", message)

    def complete_round(self, round_id: str) -> Any:
        """Persist feedback first, then close RoundManager with the saved reference."""
        feedback = self.build_feedback_record(round_id)
        feedback_ref = self.feedback_store.save(feedback)
        decision_status = feedback["decision"]["status"].lower()
        return self.manager.complete(round_id, decision_status, feedback_ref)

    def _load(self, contract: str, reference: str) -> dict:
        payload = self.artifacts.load(contract, reference)
        return self.validator.validate(contract, payload)

    def _audit_outbound_input(
        self,
        component: str,
        state: RoundState,
        record: Any,
        payload: Mapping[str, Any],
        *,
        contract_name: str,
        input_artifact_refs: Mapping[str, str],
        output_artifact_refs: Optional[Mapping[str, str]] = None,
    ) -> None:
        if self.audit_writer is None:
            return
        refs = dict(input_artifact_refs)
        request_rows = self.artifacts.find_by_task("round_request", record.round_id)
        if request_rows:
            refs.setdefault("round_request", request_rows[0][0])
        self.audit_writer.record(
            "outbound_input_prepared",
            record.round_id,
            component=component,
            step_state=state.value,
            based_on_transition_sequence=record.transitions[-1].sequence,
            status="validated",
            versions=record.config.pinned_versions(),
            input_contract=contract_name,
            input_contract_version=payload.get("contract_version"),
            input_artifact_refs=refs,
            input_payload=payload,
            output_artifact_refs=dict(output_artifact_refs or {}),
            validation={"status": "accepted"},
            detail=f"validated {component} input assembled",
        )


__all__ = [
    "ContractAlignmentError",
    "IncompleteEvidenceError",
    "InvalidCrossContract",
    "OrchestratorOutputAdapter",
]
