"""Exceptions raised by round management.

Every exception carries an ``error_category`` that lines up with the categories
the shared ``error_response`` contract is expected to define (validation,
dependency, timeout, retry). Adjust the strings here if the team settles on
different names.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

ROUND_ERROR_CATEGORIES = ("validation", "dependency", "timeout", "retry", "internal")


class RoundManagementError(Exception):
    """Base class for all round management errors."""

    error_category = "internal"
    retryable = False

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class InvalidRoundRequestError(RoundManagementError):
    error_category = "validation"

    def __init__(self, problems: List[str]):
        super().__init__("Invalid round request: " + "; ".join(problems), {"problems": problems})
        self.problems = problems


class InvalidTransitionError(RoundManagementError):
    error_category = "validation"


class InvalidArgumentError(RoundManagementError):
    """A method argument is invalid independently of the round's current state."""

    error_category = "validation"


class RoundNotFoundError(RoundManagementError):
    error_category = "validation"


class RoundClosedError(RoundManagementError):
    error_category = "validation"


class RetryExhaustedError(RoundManagementError):
    error_category = "retry"


class RoundTimedOutError(RoundManagementError):
    error_category = "timeout"


class ConcurrencyError(RoundManagementError):
    error_category = "conflict"
    retryable = True


class IntegrityError(RoundManagementError):
    error_category = "integrity"
