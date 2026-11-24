"""Load the JSON Schema contract files shipped with the package.

The authoritative contracts live in the repository (``00_shared_contracts/`` and
``03_blue_role/interfaces/inputs/``). A copy is shipped inside the package
(``autosoc_blue/contracts/``) so the package works when installed on its own,
with no access to the rest of the project. A test checks that the shipped copy
and the repository originals are identical, so they cannot drift silently.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

CONTRACTS_DIR = Path(__file__).resolve().parents[1] / "contracts"

SCHEMA_FILES: dict[str, Path] = {
    "blue_proposal": CONTRACTS_DIR / "blue_proposal.schema.json",
    "blue_input": CONTRACTS_DIR / "blue_input.schema.json",
    "error_response": CONTRACTS_DIR / "error_response.schema.json",
    "evidence_reference": CONTRACTS_DIR / "evidence_reference.schema.json",
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
