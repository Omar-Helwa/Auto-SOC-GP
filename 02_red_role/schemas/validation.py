"""B3 — local validation against the contract schemas.

Validation always runs against the loaded JSON Schema files (source of
truth), never a hand-maintained copy of the rules. Results are returned as
structured objects so callers can branch on them and build error responses.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from jsonschema import Draft202012Validator

from ._loader import load_schema


@dataclass(frozen=True)
class FieldError:
    """One schema violation, flattened for easy reporting."""

    path: str          # e.g. "scenario/workflow_steps/0/action" or "(root)"
    message: str       # human-readable reason from jsonschema
    keyword: str       # the schema keyword that failed: required/enum/type/...


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of validating an instance against a contract."""

    ok: bool
    errors: tuple[FieldError, ...] = field(default_factory=tuple)

    def __bool__(self) -> bool:  # allow `if validate_...(x):`
        return self.ok

    @property
    def has_missing_required(self) -> bool:
        return any(e.keyword == "required" for e in self.errors)

    def summary(self) -> str:
        if self.ok:
            return "valid"
        return "; ".join(f"{e.path}: {e.message}" for e in self.errors)


def _validator(schema_name: str) -> Draft202012Validator:
    return Draft202012Validator(load_schema(schema_name))


def validate(instance, schema_name: str) -> ValidationResult:
    """Validate ``instance`` against the named contract schema."""
    errors: list[FieldError] = []
    for err in sorted(
        _validator(schema_name).iter_errors(instance),
        key=lambda e: list(e.path),
    ):
        path = "/".join(str(p) for p in err.path) or "(root)"
        errors.append(FieldError(path=path, message=err.message, keyword=err.validator))
    return ValidationResult(ok=not errors, errors=tuple(errors))


# Convenience wrappers for the contracts the Red component touches.
def validate_red_proposal(instance) -> ValidationResult:
    """Validate something the Red component is about to EMIT."""
    return validate(instance, "red_proposal")


def validate_red_input(instance) -> ValidationResult:
    """Validate something the Red component RECEIVES."""
    return validate(instance, "red_input")


def validate_error_response(instance) -> ValidationResult:
    return validate(instance, "error_response")


def validate_evidence_reference(instance) -> ValidationResult:
    return validate(instance, "evidence_reference")


def input_error_category(result: ValidationResult) -> str:
    """Classify a failed red-input validation into an error_response category.

    Missing required fields -> ``missing_information`` (the caller didn't give
    red enough to work with). Anything else (wrong type, out-of-enum, too many
    steps) -> ``validation`` (the caller sent a malformed request).
    """
    if result.ok:
        raise ValueError("input_error_category called on a valid result")
    return "missing_information" if result.has_missing_required else "validation"
