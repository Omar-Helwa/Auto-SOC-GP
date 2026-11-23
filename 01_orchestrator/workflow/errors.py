"""Workflow-level errors for dependency failures and blocked integration points."""

from __future__ import annotations

from typing import Any, Mapping, Optional


class WorkflowBlockedError(RuntimeError):
    """A round cannot advance until its configuration or integration is fixed."""

    def __init__(self, message: str, *, round_id: str, state: str, details: Optional[Mapping[str, Any]] = None):
        super().__init__(message)
        self.round_id = round_id
        self.state = state
        self.details = dict(details or {})


class WorkflowServiceError(RuntimeError):
    """A workflow dependency returned a classified failure."""

    def __init__(
        self,
        message: str,
        *,
        category: str = "dependency",
        retryable: bool = False,
        details: Optional[Mapping[str, Any]] = None,
    ):
        if category not in {"validation", "missing_information", "dependency", "timeout", "internal"}:
            raise ValueError(f"Unsupported error_response category: {category!r}")
        super().__init__(message)
        self.category = category
        self.retryable = retryable
        self.details = dict(details or {})


class WorkflowAuditError(RuntimeError):
    """A required audit event could not be written."""


class WorkflowPersistenceError(RuntimeError):
    """Persistence failed after the component attempt stopped being active."""
