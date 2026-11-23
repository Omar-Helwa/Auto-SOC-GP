"""Resolve schemas used by the Mongo repository.

Published schemas in ``00_shared_contracts`` take precedence. The Red input
schema is registered for the auxiliary red_input document. The full shared
telemetry_evidence schema is pending, so its existing Orchestrator temporary
envelope schema is used as a clearly reported fallback. Other messages with
no available schema are stored unvalidated with a warning.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012


def _find_repo_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "00_shared_contracts").is_dir():
            return candidate
    raise RuntimeError(f"Could not locate repo root above {start}")


REPO_ROOT = _find_repo_root(Path(__file__).resolve())
SHARED = REPO_ROOT / "00_shared_contracts"
RED = REPO_ROOT / "02_red_role"
ORCHESTRATOR = REPO_ROOT / "01_orchestrator"

# Contract name -> schema file path. A path may not exist yet; that is expected.
SCHEMA_FILES: dict[str, Path] = {
    "round_request": SHARED / "round_request" / "round_request.schema.json",
    "red_proposal": SHARED / "red_proposal" / "red_proposal.schema.json",
    "telemetry_evidence": SHARED / "telemetry_evidence" / "telemetry_evidence.schema.json",
    "reviewed_label_set": SHARED / "telemetry_evidence" / "reviewed_label_set.schema.json",
    "blue_proposal": SHARED / "blue_proposal" / "blue_proposal.schema.json",
    "candidate_rule": SHARED / "candidate_rule" / "candidate_rule.schema.json",
    "match_set": SHARED / "candidate_rule" / "match_set.schema.json",
    "judge_result": SHARED / "judge_result" / "judge_result.schema.json",
    "feedback_record": SHARED / "feedback_record" / "feedback_record.schema.json",
    "error_response": SHARED / "error_response" / "error_response.schema.json",
    # Non-boundary / citation schemas:
    "red_input": RED / "interfaces" / "inputs" / "red_input.schema.json",
    "evidence_reference": SHARED / "telemetry_evidence" / "evidence_reference.schema.json",
}

# The full shared telemetry_evidence schema is pending. Until it is published,
# validate the Orchestrator's explicitly temporary boundary envelope. A future
# shared schema takes precedence on the next process start (schemas are cached).
TEMPORARY_SCHEMA_FILES: dict[str, Path] = {
    "telemetry_evidence": ORCHESTRATOR / "interfaces" / "contracts" / "telemetry_evidence.schema.json",
}


def _schema_path(name: str) -> Path | None:
    canonical = SCHEMA_FILES.get(name)
    if canonical is not None and canonical.is_file():
        return canonical
    temporary = TEMPORARY_SCHEMA_FILES.get(name)
    if temporary is not None and temporary.is_file():
        return temporary
    return None


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict | None:
    """Return the canonical or explicitly temporary schema, if available."""
    path = _schema_path(name)
    if path is None:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def has_schema(name: str) -> bool:
    return load_schema(name) is not None


def available_contracts() -> list[str]:
    """Mapped messages that currently have a canonical or fallback schema."""
    return sorted(n for n in SCHEMA_FILES if has_schema(n))


def missing_contracts() -> list[str]:
    """Contracts still waiting on a schema (stored unvalidated for now)."""
    return sorted(n for n in SCHEMA_FILES if not has_schema(n))


def temporary_contracts() -> list[str]:
    """Messages currently validated using a temporary fallback schema."""
    return sorted(
        name for name, temporary in TEMPORARY_SCHEMA_FILES.items()
        if temporary.is_file()
        and (SCHEMA_FILES.get(name) is None or not SCHEMA_FILES[name].is_file())
    )


@lru_cache(maxsize=1)
def build_registry() -> Registry:
    """Registry of every available schema, keyed by its ``$id``.

    Schemas reference each other by ``$id`` (``autosoc://contracts/...``), which
    is not a fetchable URL, so a validator must be given this registry or any
    ``$ref`` fails to resolve (for example ``round_request.permitted_evidence_refs``).
    """
    paths = sorted(SHARED.rglob("*.schema.json")) + [SCHEMA_FILES["red_input"]]
    paths.extend(TEMPORARY_SCHEMA_FILES[name] for name in temporary_contracts())
    resources = []
    for path in paths:
        if not path.is_file():
            continue
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema, DRAFT202012)))
    return Registry().with_resources(resources)
