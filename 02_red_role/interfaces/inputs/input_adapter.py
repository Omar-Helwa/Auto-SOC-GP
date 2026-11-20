"""Validate + parse an incoming red_input (Epic G1).

Validates the raw dict against the red_input schema, then returns a typed
RedInput. On failure it raises InputError carrying the right error_response
category (missing_information vs validation), which the component turns into a
contract-valid error.
"""

from __future__ import annotations

from schemas import validation
from schemas.models import RedInput


class InputError(Exception):
    def __init__(self, category: str, message: str, details: dict | None = None):
        super().__init__(message)
        self.category = category
        self.message = message
        self.details = details or {}


def parse_and_validate_input(raw: dict) -> RedInput:
    if not isinstance(raw, dict):
        raise InputError("validation", "red_input must be a JSON object")

    result = validation.validate_red_input(raw)
    if not result.ok:
        category = validation.input_error_category(result)
        raise InputError(
            category,
            f"red_input failed validation: {result.summary()}",
            details={"errors": [e.path for e in result.errors]},
        )
    return RedInput.from_dict(raw)
