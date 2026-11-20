"""Test harness for the Red component.

Adds the component root (``02_red_role``) to sys.path so ``import schemas``
works regardless of the current working directory, and exposes helpers to
load the shared contract example files.

Run from the component root:
    cd 02_red_role && python -m pytest
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# dev/tests/conftest.py -> parents[2] == 02_red_role
COMPONENT_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = COMPONENT_ROOT.parent

if str(COMPONENT_ROOT) not in sys.path:
    sys.path.insert(0, str(COMPONENT_ROOT))


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _strip_helper_keys(data):
    """Example files carry a ``_why_invalid`` annotation; drop it before use."""
    if isinstance(data, dict):
        return {k: v for k, v in data.items() if not k.startswith("_")}
    return data


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def example():
    """Return a loader: example('red_proposal', 'valid') -> dict (helpers stripped)."""
    locations = {
        "red_proposal": REPO_ROOT / "00_shared_contracts" / "red_proposal" / "examples",
        "red_input": COMPONENT_ROOT / "interfaces" / "inputs" / "examples",
        "error_response": REPO_ROOT / "00_shared_contracts" / "error_response" / "examples",
        "evidence_reference": REPO_ROOT
        / "00_shared_contracts"
        / "telemetry_evidence"
        / "examples",
    }

    def _get(contract: str, kind: str):
        folder = locations[contract]
        fname = f"{kind}_{contract}.json"
        return _strip_helper_keys(_load_json(folder / fname))

    return _get
