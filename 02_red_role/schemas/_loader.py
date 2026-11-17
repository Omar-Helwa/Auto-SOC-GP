"""Locate and load the authoritative JSON Schema contract files.

The schemas in ``00_shared_contracts/`` (and the red-owned ``red_input``
schema under this component) are the single source of truth. This module
finds them relative to the repository root and caches the parsed JSON.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path


def _find_repo_root(start: Path) -> Path:
    """Walk upward until we find the folder that holds 00_shared_contracts."""
    for candidate in (start, *start.parents):
        if (candidate / "00_shared_contracts").is_dir():
            return candidate
    raise RuntimeError(
        f"Could not locate repo root (no 00_shared_contracts/) above {start}"
    )


REPO_ROOT = _find_repo_root(Path(__file__).resolve())

SHARED = REPO_ROOT / "00_shared_contracts"
RED = REPO_ROOT / "02_red_role"

# Contract name -> schema file path.
SCHEMA_FILES: dict[str, Path] = {
    "red_proposal": SHARED / "red_proposal" / "red_proposal.schema.json",
    "red_input": RED / "interfaces" / "inputs" / "red_input.schema.json",
    "error_response": SHARED / "error_response" / "error_response.schema.json",
    "evidence_reference": SHARED
    / "telemetry_evidence"
    / "evidence_reference.schema.json",
}


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict:
    """Return the parsed JSON Schema for a contract name."""
    try:
        path = SCHEMA_FILES[name]
    except KeyError:
        raise KeyError(
            f"Unknown contract '{name}'. Known: {sorted(SCHEMA_FILES)}"
        ) from None
    if not path.is_file():
        raise FileNotFoundError(f"Schema file missing for '{name}': {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def schema_enum(name: str, pointer: tuple[str, ...]) -> list:
    """Read an ``enum`` list out of a loaded schema by a simple key path.

    Used by the drift test to compare Python constants against the schema.
    ``pointer`` is a sequence of keys descending into the schema dict.
    """
    node = load_schema(name)
    for key in pointer:
        node = node[key]
    return node["enum"]
