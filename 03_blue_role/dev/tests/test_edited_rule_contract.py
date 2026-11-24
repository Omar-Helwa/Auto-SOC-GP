"""The optional edited_rule field of blue_proposal (0.1.0, additive)."""

import json
from pathlib import Path

from autosoc_blue.role import BlueRole
from autosoc_blue.schemas import validation

REPO = Path(__file__).resolve().parents[3]
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "inputs"


def _input(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_shared_spl_example_is_valid():
    example = json.loads(
        (REPO / "00_shared_contracts" / "blue_proposal" / "examples" / "valid_blue_proposal_spl.json").read_text(encoding="utf-8"))
    assert validation.validate_blue_proposal(example).ok
    assert example["edited_rule"]["format"] == "spl"


def test_edited_rule_is_off_by_default():
    out = BlueRole().run(_input("spl_single_fp.json"))
    assert "edited_rule" not in out
    assert validation.validate_blue_proposal(out).ok


def test_embedded_edited_rule_spl_input():
    out = BlueRole(embed_edited_rule=True).run(_input("spl_single_fp.json"))
    assert validation.validate_blue_proposal(out).ok
    assert out["edited_rule"]["format"] == "spl"
    text = out["edited_rule"]["text"]
    assert text.startswith("index=winlogs ")
    assert "NOT (User=" in text and "svc_inventory" in text and "svchost.exe" in text


def test_embedded_edited_rule_sigma_input():
    out = BlueRole(embed_edited_rule=True).run(_input("single_fp.json"))
    assert validation.validate_blue_proposal(out).ok
    assert out["edited_rule"]["format"] == "sigma"


def test_edited_rule_rejects_unknown_format():
    bad = BlueRole(embed_edited_rule=True).run(_input("single_fp.json"))
    bad["edited_rule"] = {"format": "kql", "text": "x"}
    assert not validation.validate_blue_proposal(bad).ok
