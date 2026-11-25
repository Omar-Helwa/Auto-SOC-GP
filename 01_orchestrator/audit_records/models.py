"""Serializable audit event model used by the workflow and persistence adapters."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional


class AuditRecordError(ValueError):
    """An audit event is incomplete or contains non-JSON data."""


@dataclass(frozen=True)
class AuditRecord:
    """One immutable round or component-call event.

    Contract messages are stored separately and referenced by URI. Input
    snapshots are embedded where they are needed to reproduce an outbound
    call, while raw model output remains represented by a durable reference.
    """

    task_id: str
    event_type: str
    occurred_at: str
    round_id: Optional[str] = None
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: Optional[str] = None
    component: Optional[str] = None
    step_state: Optional[str] = None
    attempt: Optional[int] = None
    based_on_transition_sequence: Optional[int] = None
    transition_sequence: Optional[int] = None
    status: Optional[str] = None
    versions: Mapping[str, str] = field(default_factory=dict)
    model_id: Optional[str] = None
    input_contract: Optional[str] = None
    input_contract_version: Optional[str] = None
    input_artifact_refs: Mapping[str, str] = field(default_factory=dict)
    input_payload: Optional[Mapping[str, Any]] = None
    output_contracts: tuple[str, ...] = ()
    output_contract_versions: Mapping[str, str] = field(default_factory=dict)
    output_artifact_refs: Mapping[str, str] = field(default_factory=dict)
    raw_output: Any = None
    raw_output_source: Optional[str] = None
    raw_output_ref: Optional[str] = None
    validation: Optional[Mapping[str, Any]] = None
    execution_refs: tuple[str, ...] = ()
    decision: Optional[Mapping[str, Any]] = None
    error: Optional[Mapping[str, Any]] = None
    detail: Optional[str] = None

    def to_document(self) -> dict[str, Any]:
        if not isinstance(self.task_id, str) or not self.task_id.strip():
            raise AuditRecordError("task_id must be a non-empty string")
        if not isinstance(self.audit_id, str) or not self.audit_id.strip():
            raise AuditRecordError("audit_id must be a non-empty string")
        if not isinstance(self.event_type, str) or not self.event_type.strip():
            raise AuditRecordError("event_type must be a non-empty string")
        if not isinstance(self.occurred_at, str) or not self.occurred_at.strip():
            raise AuditRecordError("occurred_at must be a non-empty ISO timestamp")
        if self.attempt is not None and (type(self.attempt) is not int or self.attempt < 1):
            raise AuditRecordError("attempt must be a positive integer")
        for field_name in ("based_on_transition_sequence", "transition_sequence"):
            value = getattr(self, field_name)
            if value is not None and (type(value) is not int or value < 1):
                raise AuditRecordError(f"{field_name} must be a positive integer")

        document: dict[str, Any] = {
            "audit_record_version": "0.2.0",
            "audit_id": self.audit_id,
            "task_id": self.task_id,
            "round_id": self.round_id or self.task_id,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "versions": dict(self.versions),
            "output_contract_versions": dict(self.output_contract_versions),
            "input_artifact_refs": dict(self.input_artifact_refs),
            "output_contracts": list(self.output_contracts),
            "output_artifact_refs": dict(self.output_artifact_refs),
            "execution_refs": list(self.execution_refs),
        }
        for name in (
            "correlation_id", "component", "step_state", "attempt",
            "based_on_transition_sequence", "transition_sequence", "status", "model_id",
            "input_contract", "input_contract_version", "input_payload", "raw_output",
            "raw_output_source", "raw_output_ref",
            "validation", "decision", "error", "detail",
        ):
            value = getattr(self, name)
            if value is not None:
                document[name] = dict(value) if isinstance(value, Mapping) else value

        try:
            # Detach from caller-owned containers and reject BSON-only values,
            # NaN, and other payloads that cannot be replayed as strict JSON.
            return json.loads(json.dumps(document, allow_nan=False))
        except (TypeError, ValueError) as exc:
            raise AuditRecordError(f"audit record must contain strict JSON values: {exc}") from exc
