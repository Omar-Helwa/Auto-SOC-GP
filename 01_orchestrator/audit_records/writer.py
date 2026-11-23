"""Build timestamped immutable audit events and write them to a store."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Optional

from .models import AuditRecord
from .store import AuditRecordStore

Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuditRecordWriter:
    def __init__(self, store: AuditRecordStore, clock: Optional[Clock] = None):
        self.store = store
        self._clock = clock or _utc_now
        self._lock = threading.Lock()
        self._last_timestamp_by_task: dict[str, datetime] = {}

    def record(
        self,
        event_type: str,
        task_id: str,
        *,
        round_id: Optional[str] = None,
        occurred_at: Optional[str] = None,
        **fields: Any,
    ) -> str:
        supplied = datetime.fromisoformat(occurred_at) if occurred_at else self._clock()
        if supplied.tzinfo is None:
            supplied = supplied.replace(tzinfo=timezone.utc)
        timestamp = supplied.astimezone(timezone.utc)
        with self._lock:
            previous = self._last_timestamp_by_task.get(task_id)
            if previous is not None and timestamp <= previous:
                timestamp = previous + timedelta(microseconds=1)
            self._last_timestamp_by_task[task_id] = timestamp
        event = AuditRecord(
            task_id=task_id,
            round_id=round_id,
            event_type=event_type,
            occurred_at=timestamp.isoformat(),
            **fields,
        )
        return self.store.append(event)

    def record_component_start(
        self,
        *,
        task_id: str,
        correlation_id: str,
        component: str,
        step_state: str,
        attempt: int,
        based_on_transition_sequence: int,
        versions: Mapping[str, str],
        input_artifact_refs: Mapping[str, str],
        input_payload: Mapping[str, Any],
        input_contract: Optional[str] = None,
        input_contract_version: Optional[str] = None,
    ) -> str:
        return self.record(
            "component_call_started",
            task_id,
            correlation_id=correlation_id,
            component=component,
            step_state=step_state,
            attempt=attempt,
            based_on_transition_sequence=based_on_transition_sequence,
            input_contract=input_contract,
            input_contract_version=input_contract_version,
            status="started",
            versions=versions,
            input_artifact_refs=input_artifact_refs,
            input_payload=input_payload,
        )

