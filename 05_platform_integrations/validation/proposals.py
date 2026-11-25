"""Contract validation for proposals and platform-produced artifacts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


def _find_repo_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "00_shared_contracts").is_dir():
            return candidate
    raise RuntimeError(f"Could not locate repository root above {start}")


_REPO_ROOT = _find_repo_root(Path(__file__).resolve())
_SCHEMAS = {
    "red_proposal": _REPO_ROOT
    / "00_shared_contracts"
    / "red_proposal"
    / "red_proposal.schema.json",
    "blue_proposal": _REPO_ROOT
    / "00_shared_contracts"
    / "blue_proposal"
    / "blue_proposal.schema.json",
    "candidate_rule": _REPO_ROOT
    / "00_shared_contracts"
    / "candidate_rule"
    / "candidate_rule.schema.json",
    "match_set": _REPO_ROOT
    / "00_shared_contracts"
    / "candidate_rule"
    / "match_set.schema.json",
    "telemetry_evidence": _REPO_ROOT
    / "00_shared_contracts"
    / "telemetry_evidence"
    / "telemetry_evidence.schema.json",
    "evidence_reference": _REPO_ROOT
    / "00_shared_contracts"
    / "telemetry_evidence"
    / "evidence_reference.schema.json",
    "reviewed_label_set": _REPO_ROOT
    / "00_shared_contracts"
    / "telemetry_evidence"
    / "reviewed_label_set.schema.json",
}


@lru_cache(maxsize=None)
def _load_schema(schema_name: str) -> dict[str, Any]:
    path = _SCHEMAS.get(schema_name)
    if path is None:
        raise ValueError(f"Unknown platform contract: {schema_name}")
    if not path.is_file():
        raise FileNotFoundError(f"Contract schema is missing: {path}")
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return schema


@lru_cache(maxsize=1)
def _schema_registry() -> Registry:
    resources = []
    for name in _SCHEMAS:
        schema = _load_schema(name)
        schema_id = schema.get("$id")
        if schema_id:
            resources.append((schema_id, Resource.from_contents(schema)))
    return Registry().with_resources(resources)


@lru_cache(maxsize=None)
def _validator(schema_name: str) -> Draft202012Validator:
    return Draft202012Validator(
        _load_schema(schema_name), registry=_schema_registry()
    )


@dataclass(frozen=True)
class ContractViolation:
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


class ContractValidationError(ValueError):
    """A malformed request or platform output, with all schema failures."""

    def __init__(self, contract: str, violations: tuple[ContractViolation, ...]):
        self.contract = contract
        self.violations = violations
        details = "; ".join(str(item) for item in violations)
        super().__init__(f"{contract} validation failed: {details}")


def validate_contract(instance: Any, schema_name: str) -> tuple[ContractViolation, ...]:
    errors = sorted(
        _validator(schema_name).iter_errors(instance),
        key=lambda error: tuple(str(part) for part in error.path),
    )
    return tuple(
        ContractViolation(
            path="/".join(str(part) for part in error.path) or "(root)",
            message=error.message,
        )
        for error in errors
    )


def require_valid_contract(instance: Any, schema_name: str) -> None:
    violations = validate_contract(instance, schema_name)
    if violations:
        raise ContractValidationError(schema_name, violations)
