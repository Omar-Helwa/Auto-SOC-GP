"""Locate and load the authoritative JSON Schema contract files.

Same approach as the Red component: the schema files are the source of truth,
found relative to the repository root and cached once parsed.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path


def _find_repo_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "00_shared_contracts").is_dir():
            return candidate
    raise RuntimeError(f"Could not locate repo root (no 00_shared_contracts/) above {start}")


REPO_ROOT = _find_repo_root(Path(__file__).resolve())

SHARED = REPO_ROOT / "00_shared_contracts"
BLUE = REPO_ROOT / "03_blue_role"

SCHEMA_FILES: dict[str, Path] = {
    "blue_proposal": SHARED / "blue_proposal" / "blue_proposal.schema.json",
    "blue_input": BLUE / "interfaces" / "inputs" / "blue_input.schema.json",
    "error_response": SHARED / "error_response" / "error_response.schema.json",
    "evidence_reference": SHARED / "telemetry_evidence" / "evidence_reference.schema.json",
}


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict:
    try:
        path = SCHEMA_FILES[name]
    except KeyError:
        raise KeyError(f"Unknown contract '{name}'. Known: {sorted(SCHEMA_FILES)}") from None
    if not path.is_file():
        raise FileNotFoundError(f"Schema file missing for '{name}': {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def schema_node(name: str, pointer: tuple[str, ...]):
    """Descend into a loaded schema by a simple key path."""
    node = load_schema(name)
    for key in pointer:
        node = node[key]
    return node


def schema_enum(name: str, pointer: tuple[str, ...]) -> list:
    return schema_node(name, pointer)["enum"]
