"""B4 (part 1) — build contract-valid error_response payloads.

When the Red component cannot produce a valid proposal it returns an
``error_response`` instead. This module is the one place that constructs
those, so the category/retryable semantics stay consistent.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from . import constants


class RedContractError(Exception):
    """Raised when the Red component would emit a non-contract-valid payload.

    This is an internal safety net: red should never serialize something that
    fails its own output schema. Callers convert it into an ``internal`` error.
    """


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
    """Construct an ``error_response`` dict for the Red component.

    ``retryable`` defaults to the standard per-category value if not given.
    The result matches error_response@0.1.0 (validated by the serializer/tests).
    """
    if category not in constants.ERROR_CATEGORIES:
        raise ValueError(
            f"Unknown error category {category!r}; allowed: {constants.ERROR_CATEGORIES}"
        )
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
