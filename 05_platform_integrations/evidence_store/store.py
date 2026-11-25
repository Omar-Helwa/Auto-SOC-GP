"""Immutable, content-verified JSON evidence persistence."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping


_EVIDENCE_ID = re.compile(r"^[A-Za-z0-9-]{1,128}$")


class EvidenceStoreError(RuntimeError):
    """Evidence could not be safely persisted or retrieved."""


class EvidenceStore:
    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def put(self, evidence: Mapping[str, Any]) -> dict[str, Any]:
        record = dict(evidence)
        evidence_id = record.get("evidence_id")
        if not isinstance(evidence_id, str) or not _EVIDENCE_ID.fullmatch(evidence_id):
            raise ValueError("evidence_id must contain only letters, digits, or hyphens")
        if "content_sha256" in record:
            raise ValueError("content_sha256 is assigned by the evidence store")
        digest = hashlib.sha256(_canonical_json(record)).hexdigest()
        stored = {**record, "content_sha256": digest}
        payload = _canonical_json(stored) + b"\n"
        destination = self._root / f"{evidence_id}.json"
        try:
            with destination.open("xb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError as exc:
            raise EvidenceStoreError(f"evidence {evidence_id!r} already exists") from exc
        except OSError as exc:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
            raise EvidenceStoreError(f"could not persist evidence {evidence_id!r}: {exc}") from exc
        return stored

    def get(self, evidence_id: str) -> dict[str, Any]:
        if not isinstance(evidence_id, str) or not _EVIDENCE_ID.fullmatch(evidence_id):
            raise ValueError("evidence_id must contain only letters, digits, or hyphens")
        path = self._root / f"{evidence_id}.json"
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise EvidenceStoreError(f"evidence {evidence_id!r} was not found") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise EvidenceStoreError(f"could not read evidence {evidence_id!r}: {exc}") from exc
        if not isinstance(record, dict) or record.get("evidence_id") != evidence_id:
            raise EvidenceStoreError(f"stored evidence {evidence_id!r} is malformed")
        digest = record.get("content_sha256")
        original = {key: value for key, value in record.items() if key != "content_sha256"}
        expected = hashlib.sha256(_canonical_json(original)).hexdigest()
        if digest != expected:
            raise EvidenceStoreError(f"stored evidence {evidence_id!r} failed integrity verification")
        return record


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
