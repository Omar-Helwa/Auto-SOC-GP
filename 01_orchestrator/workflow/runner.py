"""State-driven coordinator for one Architecture 1 round."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any, Callable, Optional

from audit_records import AuditRecordWriter, InMemoryAuditRecordStore
from orchestrator_interfaces.inputs.adapter import ComponentFailure
from round_management.errors import make_error_response
from round_management.states import RoundState, is_terminal

from .errors import WorkflowAuditError, WorkflowBlockedError, WorkflowPersistenceError, WorkflowServiceError
from .models import BlueInputContext, WorkflowInvocation, WorkflowResult, WorkflowStepOutput


_COMPONENTS = {
    RoundState.RED_PROPOSED: "red_role",
    RoundState.TELEMETRY_COLLECTED: "platform",
    RoundState.EVIDENCE_VERIFIED: "platform",
    RoundState.BLUE_PROPOSED: "blue_role",
    RoundState.CANDIDATE_EXECUTED: "platform",
    RoundState.JUDGED: "deterministic_judge",
}

_INPUT_CONTRACTS = {
    RoundState.RED_PROPOSED: "red_input",
    RoundState.BLUE_PROPOSED: "blue_input",
    RoundState.JUDGED: "judge_input",
}


class RoundWorkflow:
    """Run/resume a round through the existing round and interface adapters.

    The input adapter remains the only route for persisted component results;
    it validates shared contracts, saves artifacts, and advances RoundManager.
    Services are injected and must return canonical contract messages.
    """

    def __init__(self, inputs: Any, outputs: Any, services: Any, audit_writer: Optional[AuditRecordWriter] = None):
        if inputs.manager is not outputs.manager:
            raise ValueError("Input and output adapters must share the same RoundManager")
        if inputs.artifacts is not outputs.artifacts:
            raise ValueError("Input and output adapters must share the same artifact store")
        self.inputs = inputs
        self.outputs = outputs
        self.manager = inputs.manager
        self.artifacts = inputs.artifacts
        self.services = services
        self.audit_writer = audit_writer or AuditRecordWriter(InMemoryAuditRecordStore())
        self.inputs.audit_writer = self.audit_writer
        self.outputs.audit_writer = self.audit_writer

    def run_round(self, round_request: Mapping[str, Any]) -> WorkflowResult:
        """Validate/open a round, then drive it until terminal or blocked."""
        record = self.inputs.open_round(round_request)
        existing_events = self.audit_writer.store.list_for_round(record.round_id)
        if not any(event.get("event_type") == "round_opened" for event in existing_events):
            self.audit_writer.record(
                "round_opened", record.round_id, status=record.state.value,
                versions=record.config.pinned_versions(), input_contract="round_request",
                input_contract_version=record.config.to_dict()["contract_version"],
                input_artifact_refs={"round_request": self._round_request_ref(record.round_id)},
                input_payload=record.config.to_dict(), detail="frozen round request accepted",
            )
        return self.run_open_round(record.round_id)

    def run_open_round(self, round_id: str) -> WorkflowResult:
        """Resume the next step for an existing nonterminal round."""
        while True:
            record = self.manager.get_round(round_id)
            if is_terminal(record.state):
                self._record_terminal(record)
                return WorkflowResult(round_id=round_id, state=record.state.value, record=record)
            state = record.state
            try:
                if state is RoundState.CREATED:
                    self._run_step(round_id, RoundState.RED_PROPOSED, self._red)
                elif state is RoundState.RED_PROPOSED:
                    self._run_step(round_id, RoundState.TELEMETRY_COLLECTED, self._collect_telemetry)
                elif state is RoundState.TELEMETRY_COLLECTED:
                    self._run_step(round_id, RoundState.EVIDENCE_VERIFIED, self._verify_evidence)
                elif state is RoundState.EVIDENCE_VERIFIED:
                    self._run_step(round_id, RoundState.BLUE_PROPOSED, self._blue)
                elif state is RoundState.BLUE_PROPOSED:
                    self._run_step(round_id, RoundState.CANDIDATE_EXECUTED, self._execute_candidate)
                elif state is RoundState.CANDIDATE_EXECUTED:
                    self._run_step(round_id, RoundState.JUDGED, self._judge)
                elif state is RoundState.JUDGED:
                    completed = self.outputs.complete_round(round_id)
                    self._record_terminal(completed)
                else:  # protects against future states lacking a workflow handler
                    raise WorkflowBlockedError(
                        f"No workflow handler is registered for {state.value}",
                        round_id=round_id,
                        state=state.value,
                    )
            except ComponentFailure as exc:
                if exc.retryable:
                    continue
                record = self.manager.get_round(round_id)
                if is_terminal(record.state):
                    self._record_terminal(record)
                    return WorkflowResult(round_id=round_id, state=record.state.value, record=record)
                raise WorkflowBlockedError(
                    str(exc), round_id=round_id, state=record.state.value,
                    details={"category": exc.category, "reference": exc.reference},
                ) from exc
            except Exception:
                # Some adapter preflight checks close the round before an
                # attempt is created (for example, incomplete Judge evidence).
                record = self.manager.get_round(round_id)
                if is_terminal(record.state):
                    self._record_terminal(record)
                    return WorkflowResult(round_id=round_id, state=record.state.value, record=record)
                raise

    def _run_step(self, round_id: str, target: RoundState, operation: Callable[[str], WorkflowInvocation]) -> None:
        """Invoke one dependency with the configured retry policy."""
        while True:
            preparation_error: Optional[Exception] = None
            invocation: Optional[WorkflowInvocation] = None
            try:
                invocation = operation(round_id)
            except Exception as exc:
                preparation_error = exc

            attempt = self.inputs.begin_attempt(round_id)
            before = self.manager.get_round(round_id)
            component = invocation.component if invocation is not None else _COMPONENTS[target]
            input_payload = invocation.input_payload if invocation is not None else {
                "round_request": before.config.to_dict(),
                "artifact_refs": dict(before.artifacts),
            }
            input_artifact_refs = dict(before.artifacts)
            input_artifact_refs["round_request"] = self._round_request_ref(round_id)
            if invocation is not None:
                input_artifact_refs.update(invocation.input_artifact_refs)
            correlation_id = str(uuid.uuid4())
            audit_context = {
                "correlation_id": correlation_id,
                "component": component,
                "step_state": target.value,
                "attempt": attempt,
                "based_on_transition_sequence": before.transitions[-1].sequence,
                "versions": before.config.pinned_versions(),
                "input_artifact_refs": input_artifact_refs,
                "input_payload": input_payload,
                "input_contract": _INPUT_CONTRACTS.get(target),
                "input_contract_version": (
                    input_payload.get("contract_version") if isinstance(input_payload, Mapping) else None
                ),
            }
            try:
                self.audit_writer.record_component_start(
                    task_id=round_id,
                    correlation_id=correlation_id,
                    component=component,
                    step_state=target.value,
                    attempt=attempt,
                    based_on_transition_sequence=before.transitions[-1].sequence,
                    versions=before.config.pinned_versions(),
                    input_artifact_refs=input_artifact_refs,
                    input_payload=input_payload,
                    input_contract=_INPUT_CONTRACTS.get(target),
                    input_contract_version=(
                        input_payload.get("contract_version") if isinstance(input_payload, Mapping) else None
                    ),
                )
            except Exception as exc:
                # Do not invoke a component if its start event was not durably
                # recorded. Retire the running attempt before surfacing this.
                try:
                    self.manager.finish_attempt(
                        round_id,
                        "failed",
                        error=f"Audit start record could not be stored: {exc}",
                        error_category="dependency",
                    )
                finally:
                    raise WorkflowAuditError(f"Could not persist audit start event for {target.value}") from exc

            output: Optional[WorkflowStepOutput] = None
            try:
                if preparation_error is not None:
                    raise preparation_error
                assert invocation is not None
                output = invocation.invoke()
                if not isinstance(output, WorkflowStepOutput):
                    raise WorkflowServiceError(
                        f"{target.value} service must return WorkflowStepOutput", category="internal"
                    )
                if target is RoundState.TELEMETRY_COLLECTED and not (
                    isinstance(output.raw_output_ref, str) and output.raw_output_ref.strip()
                ):
                    raise WorkflowServiceError(
                        "Telemetry collection must return a non-empty raw_output_ref", category="missing_information"
                    )
                if target is RoundState.CANDIDATE_EXECUTED:
                    record = self.manager.get_round(round_id)
                    if "baseline_match_set" not in record.artifacts and "baseline_match_set" not in output.messages:
                        raise WorkflowServiceError(
                            "Candidate execution must provide baseline_match_set when evidence verification did not",
                            category="missing_information",
                        )
                self.inputs.accept_step_result(
                    round_id,
                    target,
                    output.messages,
                    raw_output_ref=output.raw_output_ref,
                    detail=output.detail,
                    audit_context={
                        **audit_context,
                        "model_id": output.model_id,
                        "raw_output": _audit_raw_output(output)[0],
                        "raw_output_source": _audit_raw_output(output)[1],
                        "execution_refs": tuple(_find_execution_refs(output.messages)),
                        "decision": (
                            output.messages.get("judge_result", {}).get("decision")
                            if isinstance(output.messages.get("judge_result"), Mapping) else None
                        ),
                    },
                )
                return
            except WorkflowAuditError:
                raise
            except ComponentFailure as exc:
                self._record_component_failure(
                    round_id, target, attempt, correlation_id, component, before,
                    input_payload, input_artifact_refs, exc, output,
                )
                if exc.retryable:
                    continue
                raise
            except Exception as exc:
                current = self.manager.get_round(round_id)
                attempt_still_running = any(
                    item.state is target and item.outcome == "running"
                    for item in current.attempt_log
                )
                if not attempt_still_running:
                    raise WorkflowPersistenceError(
                        f"Persistence failed after the {target.value} attempt was finalized; "
                        "resume the round from its stored state"
                    ) from exc
                self._record_component_failure(
                    round_id, target, attempt, correlation_id, component, before,
                    input_payload, input_artifact_refs, exc, output,
                )
                category = getattr(exc, "category", getattr(exc, "error_category", "internal"))
                retryable = getattr(exc, "retryable", False)
                if category not in {"validation", "missing_information", "dependency", "timeout", "internal"}:
                    category = "internal"
                    retryable = False
                try:
                    error = make_error_response(
                        category,
                        str(exc) or exc.__class__.__name__,
                        task_id=round_id,
                        retryable=bool(retryable),
                        details=getattr(exc, "details", {"exception_type": exc.__class__.__name__}),
                    )
                    self.inputs.accept_error_response(
                        round_id, error,
                        raw_output_ref=output.raw_output_ref if output is not None else None,
                        audit_context={
                            **audit_context,
                            "raw_output": _audit_raw_output(output)[0] if output is not None else None,
                            "raw_output_source": _audit_raw_output(output)[1] if output is not None else None,
                            "model_id": output.model_id if output is not None else None,
                        },
                    )
                except ComponentFailure as failure:
                    if failure.retryable:
                        continue
                    raise

    def _record_component_failure(
        self, round_id: str, target: RoundState, attempt: int, correlation_id: str,
        component: str, before: Any, input_payload: Mapping[str, Any],
        input_artifact_refs: Mapping[str, str], error: Exception,
        output: Optional[WorkflowStepOutput],
    ) -> None:
        category = getattr(error, "category", "validation" if isinstance(error, ComponentFailure) else "internal")
        retryable = bool(getattr(error, "retryable", False))
        raw_ref = output.raw_output_ref if output is not None else None
        current = self.manager.get_round(round_id)
        terminal_transition_sequence = (
            current.transitions[-1].sequence
            if is_terminal(current.state) and current.transitions else None
        )
        raw_output, raw_output_source = _audit_raw_output(output) if output is not None else (None, None)
        try:
            self.audit_writer.record(
                "component_call_failed", round_id, correlation_id=correlation_id,
                component=component, step_state=target.value, attempt=attempt, status="failed",
                based_on_transition_sequence=before.transitions[-1].sequence,
                transition_sequence=terminal_transition_sequence,
                versions=before.config.pinned_versions(),
                model_id=output.model_id if output is not None else None,
                input_artifact_refs=dict(input_artifact_refs),
                input_payload=input_payload,
                output_contracts=tuple(output.messages) if output is not None else (),
                output_contract_versions=_contract_versions(output.messages) if output is not None else {},
                raw_output_ref=raw_ref,
                raw_output=raw_output,
                raw_output_source=raw_output_source,
                validation={"status": "rejected" if category == "validation" else "not_accepted"},
                execution_refs=tuple(_find_execution_refs(output.messages)) if output is not None else (),
                error={"category": category, "retryable": retryable, "message": str(error),
                       "details": getattr(error, "details", {})},
                detail=f"{component} call failed",
            )
        except Exception as audit_exc:
            current = self.manager.get_round(round_id)
            if not is_terminal(current.state):
                try:
                    self.manager.finish_attempt(
                        round_id, "failed", error=f"Audit failure: {audit_exc}", error_category="dependency",
                        raw_output_ref=raw_ref,
                    )
                except Exception:
                    pass
            raise WorkflowAuditError(f"Could not persist audit failure event for {target.value}") from audit_exc

    def _record_terminal(self, record: Any) -> None:
        # A process may stop after the round state is committed but before its
        # close event is written. Checking by round makes resume idempotent.
        events = self.audit_writer.store.list_for_round(record.round_id)
        if any(event.get("event_type") == "round_closed" for event in events):
            return
        self.audit_writer.record(
            "round_closed", record.round_id, status=record.state.value,
            transition_sequence=record.transitions[-1].sequence if record.transitions else None,
            versions=record.config.pinned_versions(),
            output_artifact_refs=dict(record.artifacts),
            decision=self._stored_decision(record.round_id),
            error=record.error if isinstance(record.error, Mapping) else None,
            detail=record.transitions[-1].detail if record.transitions else "round closed",
        )

    def _stored_decision(self, round_id: str) -> Optional[Mapping[str, Any]]:
        record = self.manager.get_round(round_id)
        reference = record.artifacts.get("judge_result")
        if not reference:
            return None
        judge_result = self.artifacts.load("judge_result", reference)
        decision = judge_result.get("decision") if isinstance(judge_result, Mapping) else None
        return dict(decision) if isinstance(decision, Mapping) else None

    def _request(self, round_id: str) -> dict:
        return self.manager.get_round(round_id).config.to_dict()

    def _round_request_ref(self, round_id: str) -> str:
        rows = self.artifacts.find_by_task("round_request", round_id)
        if not rows:
            raise WorkflowAuditError(f"No persisted round_request artifact found for {round_id}")
        return rows[0][0]

    def _artifact(self, round_id: str, name: str, contract: Optional[str] = None) -> dict:
        record = self.manager.get_round(round_id)
        reference = record.artifacts.get(name)
        if not reference:
            raise WorkflowServiceError(
                f"Required round artifact {name!r} is missing", category="missing_information",
                details={"artifact": name, "state": record.state.value},
            )
        return self.artifacts.load(contract or name, reference)

    def _red(self, round_id: str) -> WorkflowInvocation:
        payload = self.outputs.build_red_input(round_id)
        red_inputs = self.artifacts.find_by_task("red_input", round_id)
        red_ref = next((reference for reference, value in red_inputs if value == payload), None)
        input_refs = {"red_input": red_ref} if red_ref else {}
        return WorkflowInvocation(
            "red_role", payload,
            lambda: _as_step_output(self.services.red.run(payload), "red_proposal"),
            input_artifact_refs=input_refs,
        )

    def _collect_telemetry(self, round_id: str) -> WorkflowInvocation:
        request = self._request(round_id)
        red = self._artifact(round_id, "red_proposal")
        return WorkflowInvocation("platform", {"round_request": request, "red_proposal": red},
                                  lambda: self.services.platform.collect_telemetry(request, red))

    def _verify_evidence(self, round_id: str) -> WorkflowInvocation:
        record = self.manager.get_round(round_id)
        attempt = next((a for a in reversed(record.attempt_log) if a.state is RoundState.TELEMETRY_COLLECTED and a.outcome == "succeeded"), None)
        if attempt is None or not attempt.raw_output_ref:
            raise WorkflowServiceError(
                "The successful telemetry attempt has no raw_output_ref", category="missing_information"
            )
        red = self._artifact(round_id, "red_proposal")
        request = self._request(round_id)
        payload = {"round_request": request, "red_proposal": red,
                   "telemetry_raw_output_ref": attempt.raw_output_ref}
        return WorkflowInvocation("platform", payload,
                                  lambda: self.services.platform.verify_evidence(request, red, attempt.raw_output_ref))

    def _blue(self, round_id: str) -> WorkflowInvocation:
        record = self.manager.get_round(round_id)
        artifacts = {
            name: self._artifact(round_id, name, contract)
            for name, contract in (
                ("red_proposal", "red_proposal"),
                ("telemetry_evidence", "telemetry_evidence"),
                ("reviewed_label_set", "reviewed_label_set"),
                ("baseline_match_set", "match_set"),
            ) if name in record.artifacts
        }
        context = self.services.platform.build_blue_context(self._request(round_id), artifacts)
        if not isinstance(context, BlueInputContext):
            raise WorkflowServiceError("Platform build_blue_context must return BlueInputContext", category="internal")
        payload = self.outputs.build_blue_input(
            round_id,
            context.evidence_view,
            context.edit_constraints,
            blue_detection=context.blue_detection,
            prior_blue_edits=context.prior_blue_edits,
        )
        snapshot = {"round_request": self._request(round_id), "artifact_payloads": artifacts,
                    "blue_input": payload}
        return WorkflowInvocation("blue_role", snapshot, lambda: _as_step_output(
            self.services.blue.run(payload), "blue_proposal"))

    def _execute_candidate(self, round_id: str) -> WorkflowInvocation:
        record = self.manager.get_round(round_id)
        baseline = (
            self._artifact(round_id, "baseline_match_set", "match_set")
            if "baseline_match_set" in record.artifacts
            else None
        )
        blue = self._artifact(round_id, "blue_proposal")
        request = self._request(round_id)
        payload = {"round_request": request, "blue_proposal": blue, "baseline_match_set": baseline}
        def invoke() -> WorkflowStepOutput:
            result = self.services.platform.execute_candidate(request, blue, baseline)
            if not isinstance(result, WorkflowStepOutput):
                raise WorkflowServiceError("Platform execute_candidate must return WorkflowStepOutput", category="internal")
            if baseline is not None and "baseline_match_set" in result.messages:
                raise WorkflowServiceError("Baseline match set is already frozen for this round", category="validation")
            return result
        return WorkflowInvocation("platform", payload, invoke)

    def _judge(self, round_id: str) -> WorkflowInvocation:
        payload = self.outputs.build_judge_input(round_id)
        return WorkflowInvocation("deterministic_judge", {"judge_input": payload},
                                  lambda: _as_step_output(self.services.judge.run(payload), "judge_result"))


def _as_step_output(value: Any, artifact_name: str) -> WorkflowStepOutput:
    if isinstance(value, WorkflowStepOutput):
        if artifact_name not in value.messages:
            raise WorkflowServiceError(
                f"Component output is missing {artifact_name!r}", category="missing_information"
            )
        return value
    if isinstance(value, Mapping):
        return WorkflowStepOutput(messages={artifact_name: value}, raw_output=value)
    raise WorkflowServiceError(
        f"Component output for {artifact_name!r} must be a contract mapping", category="internal"
    )


def _audit_raw_output(output: WorkflowStepOutput) -> tuple[Any, str]:
    if output.raw_output is not None:
        return output.raw_output, "service_raw_response"
    return dict(output.messages), "structured_component_output"


def _contract_versions(messages: Mapping[str, Any]) -> dict[str, str]:
    versions: dict[str, str] = {}
    for name, payload in messages.items():
        if isinstance(payload, Mapping):
            version = payload.get("contract_version")
            if isinstance(version, str):
                versions[name] = version
    return versions


def _find_execution_refs(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key in {"execution_id", "execution_ref"} and isinstance(child, str) and child not in found:
                found.append(child)
            else:
                found.extend(ref for ref in _find_execution_refs(child) if ref not in found)
    elif isinstance(value, (list, tuple)):
        for child in value:
            found.extend(ref for ref in _find_execution_refs(child) if ref not in found)
    return found

