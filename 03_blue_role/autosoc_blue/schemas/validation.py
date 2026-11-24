"""Local validation against the contract schemas.

Validation always runs against the loaded JSON Schema files, never a
hand-maintained copy of the rules. Results are structured so callers can
branch on them and build error responses.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from jsonschema import Draft202012Validator

from ._loader import load_schema


@dataclass(frozen=True)
class FieldError:
    path: str
    message: str
    keyword: str


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: tuple[FieldError, ...] = field(default_factory=tuple)

    def __bool__(self) -> bool:
        return self.ok

    @property
    def has_missing_required(self) -> bool:
        return any(e.keyword == "required" for e in self.errors)

    def summary(self) -> str:
        if self.ok:
            return "valid"
        return "; ".join(f"{e.path}: {e.message}" for e in self.errors)


def validate(instance, schema_name: str) -> ValidationResult:
    validator = Draft202012Validator(load_schema(schema_name))
    errors = [
        FieldError(
            path="/".join(str(p) for p in err.path) or "(root)",
            message=err.message,
            keyword=err.validator,
        )
        for err in sorted(validator.iter_errors(instance), key=lambda e: [str(p) for p in e.path])
    ]
    return ValidationResult(ok=not errors, errors=tuple(errors))


def validate_blue_proposal(instance) -> ValidationResult:
    """Validate something the Blue component is about to EMIT."""
    return validate(instance, "blue_proposal")


def validate_blue_input(instance) -> ValidationResult:
    """Validate something the Blue component RECEIVES."""
    return validate(instance, "blue_input")


def validate_error_response(instance) -> ValidationResult:
    return validate(instance, "error_response")


def input_error_category(result: ValidationResult) -> str:
    """Missing required fields -> missing_information; anything else -> validation."""
    if result.ok:
        raise ValueError("input_error_category() called on a valid result")
    return "missing_information" if result.has_missing_required else "validation"
