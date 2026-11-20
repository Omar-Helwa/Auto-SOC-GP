"""Discover and load the shared contract JSON Schemas.

The schemas in ``00_shared_contracts/`` (plus the red-owned ``red_input``) are
the single source of truth for what a stored document must look like. This
module maps each contract name to its schema file and loads it on demand.

Not every contract has a published schema yet (some are owned by members who
have not delivered theirs). ``load_schema`` returns ``None`` for those, and the
repository stores such documents unvalidated with a warning until the schema
lands. No change to this file is needed when a schema appears — only that the
file exists at the mapped path.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path


def _find_repo_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "00_shared_contracts").is_dir():
            return candidate
    raise RuntimeError(f"Could not locate repo root above {start}")


REPO_ROOT = _find_repo_root(Path(__file__).resolve())
SHARED = REPO_ROOT / "00_shared_contracts"
RED = REPO_ROOT / "02_red_role"

# Contract name -> schema file path. A path may not exist yet; that is expected.
SCHEMA_FILES: dict[str, Path] = {
    "round_request": SHARED / "round_request" / "round_request.schema.json",
    "red_proposal": SHARED / "red_proposal" / "red_proposal.schema.json",
    # Full telemetry_evidence contract is Member 5's deliverable (not yet here).
    "telemetry_evidence": SHARED / "telemetry_evidence" / "telemetry_evidence.schema.json",
    "blue_proposal": SHARED / "blue_proposal" / "blue_proposal.schema.json",
    "candidate_rule": SHARED / "candidate_rule" / "candidate_rule.schema.json",
    "judge_result": SHARED / "judge_result" / "judge_result.schema.json",
    "feedback_record": SHARED / "feedback_record" / "feedback_record.schema.json",
    "error_response": SHARED / "error_response" / "error_response.schema.json",
    # Non-boundary / citation schemas:
    "red_input": RED / "interfaces" / "inputs" / "red_input.schema.json",
    "evidence_reference": SHARED / "telemetry_evidence" / "evidence_reference.schema.json",
}


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict | None:
    """Return the parsed schema for a contract, or None if none is published."""
    path = SCHEMA_FILES.get(name)
    if path is None or not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def has_schema(name: str) -> bool:
    return load_schema(name) is not None


def available_contracts() -> list[str]:
    """Contracts that currently have a published schema (validation enforced)."""
    return sorted(n for n in SCHEMA_FILES if has_schema(n))


def missing_contracts() -> list[str]:
    """Contracts still waiting on a schema (stored unvalidated for now)."""
    return sorted(n for n in SCHEMA_FILES if not has_schema(n))
