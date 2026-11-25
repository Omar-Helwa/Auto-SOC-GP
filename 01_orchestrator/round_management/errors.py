"""Exceptions raised by round management.

Every exception maps onto the shared ``error_response`` contract through
``to_error_response()``: ``error_category`` is one of the contract's categories
(validation, missing_information, dependency, timeout, internal) and
``retryable`` says whether the orchestrator may retry the same request.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Dict, List, Optional

from .contracts import CONTRACT_VERSION, ERROR_CATEGORIES, SOURCE_COMPONENT

ROUND_ERROR_CATEGORIES = ERROR_CATEGORIES


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def make_error_response(
    category: str,
    message: str,
    *,
    task_id: Optional[str] = None,
    retryable: bool = False,
    details: Optional[Dict[str, Any]] = None,
    error_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an ``error_response`` contract message produced by the orchestrator.

    Raises ``ValueError`` for anything the contract would reject: an unknown
    category, an empty message, error_id or task_id, a non-boolean retryable,
    details that are not a strict-JSON object, or a timestamp that is not an
    ISO-8601 date-time with a time zone.
    """
    if category not in ERROR_CATEGORIES:
        raise ValueError(f"Unknown error category: {category!r}")
    if not isinstance(message, str) or not message.strip():
        raise ValueError("message must be a non-empty string")
    if error_id is not None and (not isinstance(error_id, str) or not error_id.strip()):
        raise ValueError("error_id must be a non-empty string")
    if task_id is not None and (not isinstance(task_id, str) or not task_id.strip()):
        raise ValueError("task_id must be a non-empty string")
    if type(retryable) is not bool:
        raise ValueError("retryable must be a boolean")
    if timestamp is not None and not _valid_timestamp(timestamp):
        raise ValueError("timestamp must be an ISO-8601 date-time with a time zone")
    response: Dict[str, Any] = {
        "contract_version": CONTRACT_VERSION,
        "error_id": error_id or str(uuid.uuid4()),
        "category": category,
        "source_component": SOURCE_COMPONENT,
        "message": message,
        "retryable": retryable,
    }
    if task_id is not None:
        response["task_id"] = task_id
    if details is not None:
        if not isinstance(details, Mapping):
            raise ValueError("details must be an object")
        try:
            # Strict-JSON round trip: rejects sets, NaN and other non-serialisable
            # values, and returns a copy the caller can no longer mutate.
            response["details"] = json.loads(json.dumps(details, allow_nan=False))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"details must contain only strict JSON values: {exc}") from exc
    if timestamp is not None:
        response["timestamp"] = timestamp
    return response


class RoundManagementError(Exception):
    """Base class for all round management errors."""

    error_category = "internal"
    retryable = False

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_error_response(
        self,
        task_id: Optional[str] = None,
        *,
        error_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return this error as a contract-valid ``error_response`` message."""
        return make_error_response(
            self.error_category,
            self.message,
            task_id=task_id,
            retryable=self.retryable,
            details=self.details,
            error_id=error_id,
            timestamp=timestamp,
        )


class InvalidRoundRequestError(RoundManagementError):
    """The round request breaks the round_request contract.

    The category is ``missing_information`` when the only problems are absent
    required fields, otherwise ``validation``.
    """

    def __init__(self, problems: List[str], missing_fields: Optional[List[str]] = None):
        missing = list(missing_fields or [])
        details: Dict[str, Any] = {"problems": list(problems), "failing_contract": "round_request@0.1.0"}
        if missing:
            details["missing_fields"] = missing
        super().__init__("Invalid round request: " + "; ".join(problems), details)
        self.problems = list(problems)
        self.missing_fields = missing
        self.error_category = (
            "missing_information" if missing and len(missing) == len(problems) else "validation"
        )


class InvalidTransitionError(RoundManagementError):
    error_category = "validation"


class InvalidArgumentError(RoundManagementError):
    """A method argument is invalid independently of the round's current state."""

    error_category = "validation"


class MissingArtifactError(RoundManagementError):
    """A state change lacks a contract message the state is required to carry."""

    error_category = "missing_information"


class RoundNotFoundError(RoundManagementError):
    error_category = "validation"


class DuplicateRoundError(RoundManagementError):
    """A round already exists for this task_id (task_id is the round id)."""

    error_category = "validation"


class RoundClosedError(RoundManagementError):
    error_category = "validation"


class RetryExhaustedError(RoundManagementError):
    """A step used all its attempts.

    The contract has no ``retry`` category, so the error carries the category of
    the last failed attempt (``internal`` if none was given) and
    ``details.reason == "retry_exhausted"``.
    """

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        category: str = "internal",
    ):
        if category not in ERROR_CATEGORIES:
            raise ValueError(f"Unknown error category: {category!r}")
        super().__init__(message, details)
        self.error_category = category


class RoundTimedOutError(RoundManagementError):
    error_category = "timeout"
    retryable = True


class ConcurrencyError(RoundManagementError):
    error_category = "internal"
    retryable = True


class IntegrityError(RoundManagementError):
    error_category = "internal"


class StoreUnavailableError(RoundManagementError):
    """The datastore could not be reached or did not answer (a dependency failure; retry later)."""

    error_category = "dependency"
    retryable = True
