"""Helpers shared by Orchestrator development mocks."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any


ORCHESTRATOR_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = ORCHESTRATOR_ROOT.parent


def load_shared_example(contract_folder: str, filename: str) -> dict[str, Any]:
    path = REPOSITORY_ROOT / "00_shared_contracts" / contract_folder / "examples" / filename
    return json.loads(path.read_text(encoding="utf-8"))


def clone(value: Any) -> Any:
    return copy.deepcopy(value)
