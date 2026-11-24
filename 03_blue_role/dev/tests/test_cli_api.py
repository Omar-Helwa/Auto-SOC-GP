"""CLI (python -m autosoc_blue) and the optional HTTP API."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from autosoc_blue.cli import main
from autosoc_blue.schemas import validation

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "dev" / "fixtures" / "inputs"
EXAMPLE = ROOT / "interfaces" / "inputs" / "examples" / "valid_blue_input.json"  # has "_" helper keys


def test_propose_writes_a_valid_proposal(tmp_path, capsys, gateway_env):
    out = tmp_path / "proposal.json"
    code = main(["propose", "--input", str(FIXTURES / "single_fp.json"), "--out", str(out), "--trace"])
    assert code == 0
    proposal = json.loads(out.read_text(encoding="utf-8"))
    assert validation.validate_blue_proposal(proposal).ok
    assert "accepted" in capsys.readouterr().err


def test_propose_accepts_the_contract_example_with_helper_keys(capsys, gateway_env):
    assert main(["propose", "--input", str(EXAMPLE)]) == 0
    assert validation.validate_blue_proposal(json.loads(capsys.readouterr().out)).ok


@pytest.mark.parametrize("provider", ["none", "mock"])
def test_propose_providers(provider, capsys, gateway_env):
    assert main(["propose", "--input", str(FIXTURES / "multi_fp.json"), "--provider", provider]) == 0
    assert validation.validate_blue_proposal(json.loads(capsys.readouterr().out)).ok


def test_propose_without_safe_edit_prints_error_response(capsys, gateway_env):
    assert main(["propose", "--input", str(FIXTURES / "inseparable.json")]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["category"] == "missing_information" and validation.validate_error_response(out).ok


def test_propose_real_provider_without_key_is_a_clear_config_error(capsys, gateway_env):
    assert main(["propose", "--input", str(FIXTURES / "single_fp.json"), "--provider", "anthropic"]) == 2
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err


def test_propose_missing_or_bad_file(tmp_path, gateway_env):
    with pytest.raises(SystemExit, match="not found"):
        main(["propose", "--input", str(tmp_path / "nope.json")])
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    with pytest.raises(SystemExit, match="not valid JSON"):
        main(["propose", "--input", str(bad)])


def test_validate_command(tmp_path, capsys):
    assert main(["validate", "--input", str(FIXTURES / "single_fp.json")]) == 0
    assert "valid blue_input" in capsys.readouterr().out
    broken = json.loads((FIXTURES / "single_fp.json").read_text(encoding="utf-8"))
    del broken["must_detect"]
    path = tmp_path / "broken.json"
    path.write_text(json.dumps(broken), encoding="utf-8")
    assert main(["validate", "--input", str(path)]) == 1
    assert "must_detect" in capsys.readouterr().out
    proposal = tmp_path / "p.json"
    main(["propose", "--input", str(FIXTURES / "single_fp.json"), "--out", str(proposal)])
    assert main(["validate", "--input", str(proposal)]) == 0
    assert "valid blue_proposal" in capsys.readouterr().out


def test_python_dash_m_entry_point(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-m", "autosoc_blue", "propose", "--input", str(FIXTURES / "single_fp.json")],
        capture_output=True, text=True, cwd=ROOT, check=False)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["edits"]


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
@pytest.fixture
def client(gateway_env):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from autosoc_blue.api import create_app

    return TestClient(create_app())


def test_http_health(client):
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["proposer"] == "deterministic"


def test_http_propose(client):
    data = json.loads((FIXTURES / "single_fp.json").read_text(encoding="utf-8"))
    resp = client.post("/propose", json=data)
    assert resp.status_code == 200
    assert validation.validate_blue_proposal(resp.json()).ok
    traced = client.post("/propose?trace=true", json=data).json()
    assert traced["trace"]["attempts"][-1]["status"] == "accepted"


def test_http_errors_are_error_responses(client):
    bad = client.post("/propose", json={"task_id": "t-1"})
    assert bad.status_code == 422 and bad.json()["category"] == "missing_information"
    assert validation.validate_error_response(bad.json()).ok
    data = json.loads((FIXTURES / "inseparable.json").read_text(encoding="utf-8"))
    nothing = client.post("/propose", json=data)
    assert nothing.status_code == 422 and nothing.json()["task_id"] == data["task_id"]
