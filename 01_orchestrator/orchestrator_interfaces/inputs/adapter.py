"""Accept round requests and component outputs through the Orchestrator boundary."""

from __future__ import annotations

from typing import Any, Mapping, Optional

from ..artifacts import ContractArtifactStore, save_once
from ..validation import ContractValidationError, InterfaceError, InterfaceValidator
from round_management.states import RoundState, next_forward_state
from round_management.errors import DuplicateRoundError, RoundNotFoundError
from round_management.models import RoundConfig
from ..outputs.cross_contract import IncompleteEvidenceError, InvalidCrossContract, validate_judge_evidence

_ARTIFACT_CONTRACTS = {
    "red_proposal": "red_proposal",
    "telemetry_evidence": "telemetry_evidence",
    "reviewed_label_set": "reviewed_label_set",
    "baseline_match_set": "match_set",
    "blue_proposal": "blue_proposal",
    "candidate_rule": "candidate_rule",
    "candidate_match_set": "match_set",
    "judge_result": "judge_result",
}

_STATE_ARTIFACTS = {
    RoundState.RED_PROPOSED: frozenset({"red_proposal"}),
    RoundState.TELEMETRY_COLLECTED: frozenset(),
    RoundState.EVIDENCE_VERIFIED: frozenset(
        {"telemetry_evidence", "reviewed_label_set", "baseline_match_set"}
    ),
    RoundState.BLUE_PROPOSED: frozenset({"blue_proposal"}),
    RoundState.CANDIDATE_EXECUTED: frozenset(
        {"candidate_rule", "candidate_match_set", "baseline_match_set"}
    ),
    RoundState.JUDGED: frozenset({"judge_result"}),
}


class ComponentFailure(InterfaceError):
    """A validated component error was persisted and applied to round policy."""

    def __init__(self, message: str, *, category: str, retryable: bool, reference: str, round_record: Any):
        super().__init__(message, {"category": category, "retryable": retryable, "reference": reference})
        self.category = category
        self.retryable = retryable
        self.reference = reference
        self.round_record = round_record


class OrchestratorInputAdapter:
    """The sole inbound adapter for round and component contract messages.

    A caller begins an attempt before invoking a role, then submits its result
    here. Successful outputs are schema/cross checked, persisted, and attached
    to the matching RoundManager transition by the returned artifact reference.
    """

    def __init__(
        self, manager, artifacts: ContractArtifactStore,
        validator: Optional[InterfaceValidator] = None, audit_writer: Any = None,
    ):
        self.manager = manager
        self.artifacts = artifacts
        self.validator = validator or InterfaceValidator()
        self.audit_writer = audit_writer

    def open_round(self, round_request: Mapping[str, Any]):
        request = self.validator.validate("round_request", round_request)
        task_id = request["task_id"]
        normalized_request = RoundConfig.from_request(request).to_dict()
        try:
            existing = self.manager.get_round(task_id)
        except RoundNotFoundError:
            # Save first so a retry after a failed round insert can reuse the
            # exact same contract document rather than create another copy.
            save_once(self.artifacts, "round_request", request)
            try:
                return self.manager.create_round(request)
            except DuplicateRoundError:
                existing = self.manager.get_round(task_id)
                if existing.config.to_dict() != normalized_request:
                    raise InterfaceError(
                        f"A different round_request is already stored for task_id {task_id!r}"
                    )
                return existing
        if existing.config.to_dict() != normalized_request:
            raise InterfaceError(f"A different round_request is already stored for task_id {task_id!r}")
        save_once(self.artifacts, "round_request", request)
        return existing

    def begin_attempt(self, round_id: str) -> int:
        """Start the next step, checking the Judge bundle before its attempt."""
        record = self.manager.get_round(round_id)
        if next_forward_state(record.state) is RoundState.JUDGED:
            try:
                self._prevalidate_judge_inputs(round_id)
            except IncompleteEvidenceError as exc:
                # Do this before begin_attempt so terminal history has no
                # stranded running attempt.
                self.manager.mark_inconclusive(round_id, str(exc), details=exc.details)
                raise
            except InvalidCrossContract as exc:
                self.manager.fail(
                    round_id,
                    category="validation",
                    message=str(exc),
                    details=exc.details,
                )
                raise
        return self.manager.begin_attempt(round_id)

    def accept_step_result(
        self,
        round_id: str,
        state: RoundState,
        messages: Optional[Mapping[str, Mapping[str, Any]]] = None,
        *,
        raw_output_ref: Optional[str] = None,
        detail: str = "",
        audit_context: Optional[Mapping[str, Any]] = None,
    ):
        """Validate/persist one step's result, then advance the existing round.

        Keys in `messages` are artifact names from `round_management.states`;
        values are their contract payloads. TELEMETRY_COLLECTED has no
        message artifact in the current shared contracts, so its execution
        reference belongs on the attempt as `raw_output_ref`.
        """
        if not isinstance(state, RoundState):
            try:
                state = RoundState(state)
            except (TypeError, ValueError) as exc:
                raise InterfaceError(f"Unknown round state: {state!r}") from exc
        record = self.manager.get_round(round_id)
        try:
            expected_state = next_forward_state(record.state)
        except ValueError as exc:
            raise InterfaceError(f"Round {round_id} has no next workflow step") from exc
        if state is not expected_state:
            raise InterfaceError(
                f"Expected result for {expected_state.value}, got {state.value}",
                {"expected_state": expected_state.value, "received_state": state.value},
            )
        self._require_running_attempt(round_id, state)

        supplied = dict(messages or {})
        permitted = _STATE_ARTIFACTS.get(state)
        if permitted is None:
            raise InterfaceError(f"State {state.value} is not a component-result boundary")
        extra = sorted(set(supplied) - permitted)
        if extra:
            return self._reject_output(
                round_id,
                f"Unexpected artifact(s) for {state.value}: {extra}",
                raw_output_ref=raw_output_ref,
                audit_context=audit_context,
            )

        validated: dict[str, dict] = {}
        try:
            for artifact_name, payload in supplied.items():
                contract = _ARTIFACT_CONTRACTS[artifact_name]
                message = self.validator.validate(contract, payload)
                payload_task_id = message.get("task_id")
                if payload_task_id is not None and payload_task_id != round_id:
                    raise ContractValidationError(
                        contract,
                        [f"task_id {payload_task_id!r} does not match active round {round_id!r}"],
                    )
                if artifact_name in ("baseline_match_set", "candidate_match_set"):
                    expected_role = "baseline" if artifact_name == "baseline_match_set" else "candidate"
                    if message.get("role") != expected_role:
                        raise ContractValidationError(
                            contract,
                            [f"{artifact_name} requires match_set.role={expected_role!r}"],
                        )
                if artifact_name == "judge_result":
                    decision = message.get("decision", {})
                    status = decision.get("status") if isinstance(decision, Mapping) else None
                    if status in ("PASS", "REJECT") and message.get("provenance", {}).get(
                        "criteria"
                    ) != record.config.criteria["thresholds"]:
                        raise ContractValidationError(
                            contract,
                            ["judge_result.provenance.criteria differs from the frozen round criteria thresholds"],
                        )
                validated[artifact_name] = message
            missing = [
                name for name in self._required_for(state)
                if name not in validated
            ]
            if missing:
                raise ContractValidationError(contract=state.value, problems=[f"missing artifact {name!r}" for name in missing])
        except ContractValidationError as exc:
            return self._reject_output(
                round_id, str(exc), details=exc.details, raw_output_ref=raw_output_ref,
                audit_context=audit_context,
            )

        if state is RoundState.JUDGED:
            try:
                self._prevalidate_judge_inputs(round_id)
            except IncompleteEvidenceError as exc:
                # The bundle was checked before the Judge attempt began. A
                # change after that check indicates an artifact-store
                # integrity problem; close through the ordinary validation
                # failure path so the running attempt is not stranded.
                return self._reject_output(
                    round_id, str(exc), details=exc.details, raw_output_ref=raw_output_ref,
                    audit_context=audit_context,
                )
            except InvalidCrossContract as exc:
                return self._reject_output(
                    round_id, str(exc), details=exc.details, raw_output_ref=raw_output_ref,
                    audit_context=audit_context,
                )

        references: dict[str, str] = {}
        for artifact_name, payload in validated.items():
            contract = _ARTIFACT_CONTRACTS[artifact_name]
            reference = save_once(self.artifacts, contract, payload)
            if not isinstance(reference, str) or not reference.strip():
                raise InterfaceError(f"Artifact store returned an invalid reference for {contract}")
            references[artifact_name] = reference

        self.manager.finish_attempt(round_id, "succeeded", raw_output_ref=raw_output_ref)
        accepted = self.manager.advance(round_id, state, detail=detail, artifacts=references)
        self._audit(
            "component_call_completed", round_id, audit_context=audit_context,
            step_state=state.value,
            transition_sequence=accepted.transitions[-1].sequence,
            status="succeeded",
            output_contracts=tuple(validated),
            output_contract_versions={
                name: payload["contract_version"]
                for name, payload in validated.items()
                if isinstance(payload.get("contract_version"), str)
            },
            output_artifact_refs=references,
            raw_output_ref=raw_output_ref,
            validation={"status": "accepted"},
            detail=detail or "validated contract artifacts stored and round advanced",
        )
        return accepted

    def accept_error_response(
        self,
        round_id: str,
        error_response: Mapping[str, Any],
        *,
        raw_output_ref: Optional[str] = None,
        audit_context: Optional[Mapping[str, Any]] = None,
    ):
        """Persist a component error, preserving retry/failure policy in the round."""
        record = self.manager.get_round(round_id)
        try:
            target = next_forward_state(record.state)
        except ValueError as exc:
            raise InterfaceError(f"Round {round_id} has no active component step") from exc
        self._require_running_attempt(round_id, target)
        try:
            message = self.validator.validate("error_response", error_response)
            if message.get("task_id") not in (None, round_id):
                raise ContractValidationError(
                    "error_response",
                    [f"task_id {message['task_id']!r} does not match active round {round_id!r}"],
                )
        except ContractValidationError as exc:
            return self._reject_output(
                round_id, str(exc), details=exc.details, raw_output_ref=raw_output_ref,
                audit_context=audit_context,
            )

        reference = self.artifacts.save("error_response", message)
        category = message["category"]
        retryable = message["retryable"]
        self.manager.finish_attempt(
            round_id,
            "failed",
            error=message["message"],
            error_category=category,
            raw_output_ref=raw_output_ref or reference,
        )
        current = self.manager.get_round(round_id)
        if not retryable and current.state not in (RoundState.FAILED, RoundState.INCONCLUSIVE, RoundState.COMPLETED):
            current = self.manager.fail(
                round_id,
                category=category,
                message=message["message"],
                retryable=False,
                details={
                    "upstream_error_id": message["error_id"],
                    "upstream_source_component": message["source_component"],
                    "upstream_error_ref": reference,
                },
            )
        self._audit(
            "error_response_persisted", round_id, audit_context=audit_context,
            status="accepted",
            output_contracts=("error_response",),
            output_contract_versions={
                "error_response": message["contract_version"]
            },
            output_artifact_refs={"error_response": reference},
            raw_output_ref=raw_output_ref,
            validation={"status": "accepted"},
            error={"category": category, "retryable": retryable, "message": message["message"]},
            transition_sequence=(current.transitions[-1].sequence if current.transitions else None)
            if current.state in (RoundState.FAILED, RoundState.INCONCLUSIVE, RoundState.COMPLETED) else None,
            detail="validated error_response stored",
        )
        raise ComponentFailure(
            message["message"],
            category=category,
            retryable=retryable and current.state not in (RoundState.FAILED, RoundState.INCONCLUSIVE, RoundState.COMPLETED),
            reference=reference,
            round_record=current,
        )

    def mark_inconclusive(self, round_id: str, reason: str, *, details: Optional[Mapping[str, Any]] = None):
        """Close safely when evidence is incomplete before asking the Judge."""
        return self.manager.mark_inconclusive(round_id, reason, details=dict(details or {}))

    @staticmethod
    def _required_for(state: RoundState) -> frozenset[str]:
        return {
            RoundState.RED_PROPOSED: frozenset({"red_proposal"}),
            RoundState.TELEMETRY_COLLECTED: frozenset(),
            RoundState.EVIDENCE_VERIFIED: frozenset({"telemetry_evidence"}),
            RoundState.BLUE_PROPOSED: frozenset({"blue_proposal"}),
            RoundState.CANDIDATE_EXECUTED: frozenset({"candidate_rule", "candidate_match_set"}),
            RoundState.JUDGED: frozenset({"judge_result"}),
        }.get(state, frozenset())

    def _require_running_attempt(self, round_id: str, state: RoundState) -> None:
        record = self.manager.get_round(round_id)
        if not any(attempt.state is state and attempt.outcome == "running" for attempt in record.attempt_log):
            raise InterfaceError(
                f"Begin the {state.value} attempt before submitting its component result",
                {"round_id": round_id, "state": state.value},
            )

    def _prevalidate_judge_inputs(self, round_id: str) -> None:
        """Reject a judge result unless its exact evidence bundle was checked."""
        record = self.manager.get_round(round_id)
        refs = record.artifacts
        needed = ("blue_proposal", "candidate_rule", "baseline_match_set", "candidate_match_set", "reviewed_label_set")
        missing = [name for name in needed if name not in refs]
        if missing:
            raise IncompleteEvidenceError(
                "Cannot accept judge_result without its required evidence references",
                {"missing_artifacts": missing},
            )
        blue = self.validator.validate("blue_proposal", self.artifacts.load("blue_proposal", refs["blue_proposal"]))
        candidate_rule = self.validator.validate("candidate_rule", self.artifacts.load("candidate_rule", refs["candidate_rule"]))
        baseline = self.validator.validate("match_set", self.artifacts.load("match_set", refs["baseline_match_set"]))
        candidate = self.validator.validate("match_set", self.artifacts.load("match_set", refs["candidate_match_set"]))
        labels = self.validator.validate("reviewed_label_set", self.artifacts.load("reviewed_label_set", refs["reviewed_label_set"]))
        validate_judge_evidence(record.config, blue, candidate_rule, baseline, candidate, labels)

    def _reject_output(
        self,
        round_id: str,
        message: str,
        *,
        details: Optional[Mapping[str, Any]] = None,
        raw_output_ref: Optional[str] = None,
        audit_context: Optional[Mapping[str, Any]] = None,
    ):
        """Invalid component output fails the round and becomes an error_response."""
        record = self.manager.get_round(round_id)
        target = next_forward_state(record.state)
        self.manager.finish_attempt(
            round_id,
            "failed",
            error=message,
            error_category="validation",
            raw_output_ref=raw_output_ref,
        )
        record = self.manager.get_round(round_id)
        if record.state not in (RoundState.FAILED, RoundState.INCONCLUSIVE, RoundState.COMPLETED):
            record = self.manager.fail(
                round_id,
                category="validation",
                message=message,
                details={"failed_in_state": target.value, **dict(details or {})},
            )
        self._audit(
            "component_output_rejected", round_id, audit_context=audit_context,
            step_state=target.value,
            transition_sequence=record.transitions[-1].sequence if record.transitions else None,
            status="rejected",
            raw_output_ref=raw_output_ref,
            validation={"status": "rejected", "details": dict(details or {}), "message": message},
            error={"category": "validation", "retryable": False, "message": message},
            detail="component output rejected by interface validation",
        )
        raise ComponentFailure(
            message,
            category="validation",
            retryable=False,
            reference="",
            round_record=record,
        )

    def _audit(
        self, event_type: str, task_id: str, *,
        audit_context: Optional[Mapping[str, Any]] = None, **fields: Any,
    ) -> None:
        if self.audit_writer is not None:
            merged = dict(audit_context or {})
            merged.update(fields)
            self.audit_writer.record(event_type, task_id, **merged)


__all__ = ["ComponentFailure", "OrchestratorInputAdapter"]
