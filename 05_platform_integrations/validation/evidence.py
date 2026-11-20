"""Validation for normalized telemetry evidence records."""

from __future__ import annotations

from collections.abc import Mapping


_OPTIONAL_TEXT_FIELDS = ("host", "source", "sourcetype", "raw")


def validate_evidence(record: Mapping[str, object]) -> None:
    """Raise ValueError unless record conforms to the platform evidence contract."""
    if not isinstance(record, Mapping):
        raise ValueError("evidence must be an object")
    for field in ("event_id", "timestamp"):
        value = record.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} must be a non-empty string")
    if not isinstance(record.get("fields"), Mapping):
        raise ValueError("fields must be an object")
    for field in _OPTIONAL_TEXT_FIELDS:
        if field in record and not isinstance(record[field], str):
            raise ValueError(f"{field} must be a string when provided")
    unknown = set(record) - {"event_id", "timestamp", "fields", *_OPTIONAL_TEXT_FIELDS}
    if unknown:
        raise ValueError(f"unsupported evidence fields: {', '.join(sorted(unknown))}")
