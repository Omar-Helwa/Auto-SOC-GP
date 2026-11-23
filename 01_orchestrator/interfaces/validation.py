"""Schema validation at the orchestrator's public contract boundary."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping


class InterfaceError(ValueError):
    """Base error raised by a public interface adapter."""

    def __init__(self, message: str, details: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.details = dict(details or {})


class ContractValidationError(InterfaceError):
    """A message does not satisfy its canonical or temporary JSON Schema."""

    def __init__(self, contract: str, problems: List[str]):
        self.contract = contract
        self.problems = list(problems)
        super().__init__(
            f"{contract} contract validation failed: " + "; ".join(self.problems),
            {"contract": contract, "problems": self.problems},
        )


class ContractSchemaUnavailable(InterfaceError):
    """No published or interface-local schema is available for a message."""


_SCHEMA_NAMES = {
    "round_request": ("00_shared_contracts/round_request/round_request.schema.json",),
    "red_input": ("02_red_role/interfaces/inputs/red_input.schema.json",),
    "red_proposal": ("00_shared_contracts/red_proposal/red_proposal.schema.json",),
    "blue_input": ("03_blue_role/interfaces/inputs/blue_input.schema.json",),
    "blue_proposal": ("00_shared_contracts/blue_proposal/blue_proposal.schema.json",),
    "telemetry_evidence": (
        "00_shared_contracts/telemetry_evidence/telemetry_evidence.schema.json",
        "01_orchestrator/interfaces/contracts/telemetry_evidence.schema.json",
    ),
    "reviewed_label_set": ("00_shared_contracts/telemetry_evidence/reviewed_label_set.schema.json",),
    "match_set": ("00_shared_contracts/candidate_rule/match_set.schema.json",),
    "candidate_rule": ("00_shared_contracts/candidate_rule/candidate_rule.schema.json",),
    "judge_input": ("01_orchestrator/interfaces/contracts/judge_input.schema.json",),
    "judge_result": ("00_shared_contracts/judge_result/judge_result.schema.json",),
    "feedback_record": ("00_shared_contracts/feedback_record/feedback_record.schema.json",),
    "error_response": ("00_shared_contracts/error_response/error_response.schema.json",),
}


class InterfaceValidator:
    """Validate named messages against shared schemas, falling back to local drafts.

    `jsonschema` is loaded only when the validator is constructed. The
    round-management package itself remains standard-library-only.
    """

    def __init__(self, repo_root: str | Path | None = None):
        try:
            from jsonschema import Draft202012Validator, FormatChecker
            from referencing import Registry, Resource
            from referencing.jsonschema import DRAFT202012
        except ImportError as exc:  # pragma: no cover - depends on installation
            raise InterfaceError(
                "Orchestrator interface adapters require jsonschema and referencing; "
                "install 01_orchestrator/requirements.txt"
            ) from exc

        self.repo_root = Path(repo_root).resolve() if repo_root else Path(__file__).resolve().parents[2]
        self._validator_cls = Draft202012Validator
        self._format_checker = FormatChecker()
        self._registry = self._build_registry(Registry, Resource, DRAFT202012)
        self._schemas: Dict[str, dict] = {}
        for name, candidates in _SCHEMA_NAMES.items():
            schema_path = next(
                (self.repo_root / candidate for candidate in candidates if (self.repo_root / candidate).is_file()),
                None,
            )
            if schema_path is not None:
                self._schemas[name] = json.loads(schema_path.read_text(encoding="utf-8"))

    def _build_registry(self, Registry, Resource, draft):
        paths = list((self.repo_root / "00_shared_contracts").rglob("*.schema.json"))
        paths.extend(
            [
                self.repo_root / "02_red_role/interfaces/inputs/red_input.schema.json",
                self.repo_root / "03_blue_role/interfaces/inputs/blue_input.schema.json",
            ]
        )
        paths.extend((self.repo_root / "01_orchestrator/interfaces/contracts").glob("*.schema.json"))
        resources = []
        seen_ids = set()
        for path in paths:
            if not path.is_file():
                continue
            schema = json.loads(path.read_text(encoding="utf-8"))
            schema_id = schema.get("$id")
            if schema_id and schema_id not in seen_ids:
                resources.append((schema_id, Resource.from_contents(schema, draft)))
                seen_ids.add(schema_id)
        return Registry().with_resources(resources)

    def has_schema(self, contract: str) -> bool:
        return contract in self._schemas

    def validate(self, contract: str, message: Mapping[str, Any]) -> dict:
        if contract not in self._schemas:
            raise ContractSchemaUnavailable(f"No schema is registered for contract {contract!r}")
        if not isinstance(message, Mapping):
            raise ContractValidationError(contract, ["message must be a JSON object"])
        try:
            normalized = json.loads(json.dumps(message, allow_nan=False))
        except (TypeError, ValueError) as exc:
            raise ContractValidationError(contract, [f"message must contain strict JSON values: {exc}"]) from exc
        validator = self._validator_cls(
            self._schemas[contract],
            registry=self._registry,
            format_checker=self._format_checker,
        )
        errors = sorted(validator.iter_errors(normalized), key=lambda error: (list(error.path), error.message))
        if errors:
            problems = [
                f"{'/'.join(str(part) for part in error.path) or '(root)'}: {error.message}"
                for error in errors
            ]
            raise ContractValidationError(contract, problems)
        return normalized


def copy_message(message: Mapping[str, Any]) -> dict:
    """Return a detached strict-JSON copy for a boundary handoff."""
    try:
        return json.loads(json.dumps(copy.deepcopy(message), allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise InterfaceError(f"message must contain strict JSON values: {exc}") from exc
