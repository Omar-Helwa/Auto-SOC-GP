"""Errors of the SPL layer. Messages are written for a human, in plain words."""

from __future__ import annotations


class SplError(ValueError):
    """The SPL text (or the rule to render) cannot be handled."""

    def __init__(self, message: str, *, construct: str | None = None):
        super().__init__(message)
        self.message = message
        self.construct = construct


class SplUnsupported(SplError):
    """A valid SPL / Sigma feature that this converter deliberately does not support."""
