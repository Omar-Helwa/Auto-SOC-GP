"""Errors the engine raises. Each carries the error_response category."""

from __future__ import annotations


class BlueError(Exception):
    category = "internal"

    def __init__(self, message: str, *, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details


class InputError(BlueError):
    """The blue_input is invalid (category: validation or missing_information)."""

    def __init__(self, message: str, *, category: str = "validation", details: dict | None = None):
        super().__init__(message, details=details)
        self.category = category


class NoProposalError(BlueError):
    """No edit passed the pre-flight checks (the evidence does not allow a safe edit)."""

    category = "missing_information"
