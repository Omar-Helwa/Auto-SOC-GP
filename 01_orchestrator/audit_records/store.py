"""Audit event store interface and Mongo/in-memory implementations."""

from __future__ import annotations

import copy
import threading
from typing import Any, Mapping, Protocol

from .models import AuditRecord, AuditRecordError


class AuditRecordStore(Protocol):
    def append(self, record: AuditRecord | Mapping[str, Any]) -> str:
        """Append an immutable audit event and return its stable reference."""

    def list_for_round(self, round_id: str) -> list[dict[str, Any]]:
        """Return a round's events in time order."""


def _document(record: AuditRecord | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(record, AuditRecord):
        return record.to_document()
    try:
        detached = json_round_trip(record)
    except (TypeError, ValueError) as exc:
        raise AuditRecordError(f"audit record must contain strict JSON values: {exc}") from exc
    for field in ("audit_id", "task_id", "round_id", "event_type", "occurred_at"):
        if not isinstance(detached.get(field), str) or not detached[field].strip():
            raise AuditRecordError(f"audit record requires a non-empty {field}")
    return detached


def json_round_trip(value: Mapping[str, Any]) -> dict[str, Any]:
    import json

    return json.loads(json.dumps(dict(value), allow_nan=False))


class InMemoryAuditRecordStore:
    """Thread-safe test/development store; not durable across process restarts."""

    def __init__(self) -> None:
        self._records: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def append(self, record: AuditRecord | Mapping[str, Any]) -> str:
        document = _document(record)
        reference = f"memory://audit_record/{document['audit_id']}"
        with self._lock:
            if reference in self._records:
                raise AuditRecordError(f"duplicate audit_id: {document['audit_id']}")
            self._records[reference] = document
        return reference

    def list_for_round(self, round_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = [copy.deepcopy(row) for row in self._records.values() if row["round_id"] == round_id]
        return sorted(rows, key=lambda row: (row["occurred_at"], row["audit_id"]))


class MongoAuditRecordStore:
    """Persist audit events in shared_services' ``audit_records`` collection.

    The repository is accepted by duck type so the Orchestrator does not
    import shared_services implementation details.
    """

    def __init__(self, repository: Any):
        self._repository = repository

    def append(self, record: AuditRecord | Mapping[str, Any]) -> str:
        document = _document(record)
        inserted_id = self._repository.save("audit_record", document)
        return f"mongo://audit_record/{inserted_id}"

    def list_for_round(self, round_id: str) -> list[dict[str, Any]]:
        if not isinstance(round_id, str) or not round_id.strip():
            raise AuditRecordError("round_id must be a non-empty string")
        cursor = self._repository.collection_for("audit_record").find(
            {"round_id": round_id}, {"_id": 0}
        )
        rows = [dict(row) for row in cursor]
        return sorted(rows, key=lambda row: (row["occurred_at"], row["audit_id"]))
