"""Persistence for round records.

``RoundStore`` is the interface; the manager depends only on it. Three
implementations exist:

* ``MongoRoundStore`` (``mongo_store.py``) - the real store: one document per
  round in MongoDB. Use it for anything shared or durable.
* ``InMemoryRoundStore`` - for tests and fake rounds.
* ``JsonFileRoundStore`` - one JSON file per round, written atomically. A
  single-process development store only: it has no cross-process locking, so
  never point two processes at the same folder.

All use optimistic concurrency: ``save`` only succeeds if the record's revision
matches what is stored, then increments the revision.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from .contracts import TASK_ID_PATTERN
from .errors import ConcurrencyError, IntegrityError, RoundManagementError
from .models import RoundRecord


class RoundStore(ABC):
    @abstractmethod
    def save(self, record: RoundRecord) -> None:
        """Persist the record (create or update) and bump ``record.revision``."""

    @abstractmethod
    def load(self, round_id: str) -> Optional[RoundRecord]:
        """Return a copy of the stored record, or None."""

    @abstractmethod
    def list_ids(self) -> List[str]:
        """Return all stored round ids, sorted."""


class InMemoryRoundStore(RoundStore):
    def __init__(self) -> None:
        self._data: Dict[str, dict] = {}
        self._lock = threading.Lock()

    def save(self, record: RoundRecord) -> None:
        with self._lock:
            existing = self._data.get(record.round_id)
            stored_rev = existing["revision"] if existing else 0
            if existing is None and record.revision != 0:
                raise ConcurrencyError("Cannot update a round that was never stored")
            if existing is not None and stored_rev != record.revision:
                raise ConcurrencyError(
                    f"Round {record.round_id} changed (stored revision {stored_rev}, "
                    f"yours {record.revision}); reload and retry"
                )
            record.revision += 1
            self._data[record.round_id] = json.loads(json.dumps(record.to_dict()))

    def load(self, round_id: str) -> Optional[RoundRecord]:
        with self._lock:
            data = self._data.get(round_id)
            return RoundRecord.from_dict(json.loads(json.dumps(data))) if data else None

    def list_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._data)


class JsonFileRoundStore(RoundStore):
    def __init__(self, directory: str) -> None:
        self._dir = directory
        os.makedirs(self._dir, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, round_id: str) -> str:
        if not TASK_ID_PATTERN.match(round_id):
            raise RoundManagementError(f"Unsafe round id: {round_id!r}")
        return os.path.join(self._dir, f"{round_id}.json")

    def _read(self, round_id: str) -> Optional[dict]:
        path = self._path(round_id)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except json.JSONDecodeError as exc:
            raise IntegrityError(f"Round {round_id}: stored JSON is corrupt") from exc

    def save(self, record: RoundRecord) -> None:
        with self._lock:
            existing = self._read(record.round_id)
            stored_rev = existing["revision"] if existing else 0
            if existing is None and record.revision != 0:
                raise ConcurrencyError("Cannot update a round that was never stored")
            if existing is not None and stored_rev != record.revision:
                raise ConcurrencyError(
                    f"Round {record.round_id} changed (stored revision {stored_rev}, "
                    f"yours {record.revision}); reload and retry"
                )
            payload_data = record.to_dict()
            payload_data["revision"] = record.revision + 1
            try:
                payload = json.dumps(payload_data, indent=2, sort_keys=True, allow_nan=False)
            except (TypeError, ValueError) as exc:
                raise IntegrityError(f"Round {record.round_id}: record is not valid JSON") from exc
            fd, tmp_path = tempfile.mkstemp(dir=self._dir, suffix=".tmp")
            record.revision += 1
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(payload)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_path, self._path(record.round_id))  # atomic swap
            except Exception:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                record.revision -= 1
                raise

    def load(self, round_id: str) -> Optional[RoundRecord]:
        with self._lock:
            data = self._read(round_id)
            return RoundRecord.from_dict(data) if data else None

    def list_ids(self) -> List[str]:
        with self._lock:
            return sorted(f[:-5] for f in os.listdir(self._dir) if f.endswith(".json"))
