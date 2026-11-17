"""Build contract-valid error_response payloads for the Blue component."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from . import constants


class BlueContractError(Exception):
    """Raised when Blue would emit a payload that fails its own output schema."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def build_error_response(
    category: str,
    message: str,
    *,
    task_id: str | None = None,
    details: dict | None = None,
    retryable: bool | None = None,
    error_id: str | None = None,
    timestamp: str | None = None,
) -> dict:
    if category not in constants.ERROR_CATEGORIES:
        raise ValueError(f"Unknown error category {category!r}; allowed: {constants.ERROR_CATEGORIES}")
    if retryable is None:
        retryable = constants.RETRYABLE_BY_CATEGORY[category]
    payload: dict = {
        "contract_version": constants.ERROR_RESPONSE_VERSION,
        "error_id": error_id or f"err-{uuid.uuid4()}",
        "category": category,
        "source_component": constants.SOURCE_COMPONENT,
        "message": message,
        "retryable": retryable,
        "timestamp": timestamp or _now_iso(),
    }
    if task_id is not None:
        payload["task_id"] = task_id
    if details is not None:
        payload["details"] = details
    return payload
