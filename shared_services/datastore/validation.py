"""App-layer validation against the contract schemas (same approach as Epic B).

A document is validated against its contract's JSON Schema before it is written
to MongoDB. The schema is the source of truth; this module never re-encodes the
rules. ``validate`` returns ``None`` when no schema is published for a contract,
which the repository treats as "store unvalidated, with a warning".
"""

from __future__ import annotations

from dataclasses import dataclass

from jsonschema import Draft202012Validator

from .schema_registry import load_schema


@dataclass(frozen=True)
class FieldError:
    path: str
    message: str
    keyword: str


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: tuple[FieldError, ...] = ()

    def __bool__(self) -> bool:
        return self.ok

    def summary(self) -> str:
        if self.ok:
            return "valid"
        return "; ".join(f"{e.path}: {e.message}" for e in self.errors)


def validate(instance, contract: str) -> ValidationResult | None:
    """Validate ``instance`` against ``contract``.

    Returns a ValidationResult, or None if no schema is published for the
    contract (so the caller can decide to store it unvalidated).
    """
    schema = load_schema(contract)
    if schema is None:
        return None

    errors: list[FieldError] = []
    validator = Draft202012Validator(schema)
    for err in sorted(validator.iter_errors(instance), key=lambda e: list(e.path)):
        path = "/".join(str(p) for p in err.path) or "(root)"
        errors.append(FieldError(path=path, message=err.message, keyword=err.validator))
    return ValidationResult(ok=not errors, errors=tuple(errors))
