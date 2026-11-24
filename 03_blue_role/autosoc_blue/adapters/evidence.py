"""EvidenceSource adapters."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping


class NullEvidenceSource:
    """Fetches nothing. The default: the input already carries the evidence."""

    def fetch(self, evidence_id: str) -> Mapping[str, str] | None:
        return None


class DictEvidenceSource:
    """In-memory source: ``{evidence_id: {field: value}}``. Good for tests and demos."""

    def __init__(self, data: Mapping[str, Mapping[str, str]]):
        self._data = dict(data)

    @classmethod
    def from_json_file(cls, path: str | Path) -> "DictEvidenceSource":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def fetch(self, evidence_id: str) -> Mapping[str, str] | None:
        return self._data.get(evidence_id)
