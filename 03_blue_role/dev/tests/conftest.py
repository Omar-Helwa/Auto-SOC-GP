"""Test harness for the Blue component.

Adds the component root (``03_blue_role``) to sys.path so ``import schemas``
works, and exposes helpers to load the contract example files.

Run from the component root:
    cd 03_blue_role && python -m pytest
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

COMPONENT_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = COMPONENT_ROOT.parent

if str(COMPONENT_ROOT) not in sys.path:
    sys.path.insert(0, str(COMPONENT_ROOT))


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _strip_helper_keys(data):
    if isinstance(data, dict):
        return {k: v for k, v in data.items() if not k.startswith("_")}
    return data


_LOCATIONS = {
    "blue_proposal": REPO_ROOT / "00_shared_contracts" / "blue_proposal" / "examples",
    "blue_input": COMPONENT_ROOT / "interfaces" / "inputs" / "examples",
    "error_response": REPO_ROOT / "00_shared_contracts" / "error_response" / "examples",
}


@pytest.fixture
def example():
    """example('blue_input', 'valid') -> a fresh dict (helper keys stripped)."""

    def _get(contract: str, kind: str):
        path = _LOCATIONS[contract] / f"{kind}_{contract}.json"
        return copy.deepcopy(_strip_helper_keys(_load_json(path)))

    return _get


FIXTURE_INPUTS = COMPONENT_ROOT / "dev" / "fixtures" / "inputs"


@pytest.fixture
def fixture_input():
    """fixture_input('single_fp') -> a fresh blue_input dict from dev/fixtures/inputs."""

    def _get(name: str):
        return copy.deepcopy(_load_json(FIXTURE_INPUTS / f"{name}.json"))

    return _get


@pytest.fixture
def gateway_env(monkeypatch):
    """Start from a clean environment for the model settings."""
    for var in ("BLUE_MODEL_PROVIDER", "BLUE_MODEL_ID", "BLUE_MOCK_MODE", "BLUE_ALLOW_PARTIAL",
                "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch
