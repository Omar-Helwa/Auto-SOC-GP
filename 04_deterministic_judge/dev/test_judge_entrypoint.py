from __future__ import annotations

import json
import importlib.util
import sys
from pathlib import Path

JUDGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = JUDGE_ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(JUDGE_ROOT) not in sys.path:
    sys.path.append(str(JUDGE_ROOT))

MOCKS = JUDGE_ROOT / "dev" / "mocks"
JUDGE_MODULE_NAME = "autosoc_test_deterministic_judge_input"


def _load_run_judge():
    module = sys.modules.get(JUDGE_MODULE_NAME)
    if module is not None:
        return module.run_judge
    module_path = JUDGE_ROOT / "interfaces" / "inputs" / "judge_input.py"
    spec = importlib.util.spec_from_file_location(JUDGE_MODULE_NAME, module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.run_judge


def _case_input(case: str = "case_001") -> dict:
    baseline = json.loads(
        (MOCKS / "baseline_matches" / f"{case}.json").read_text(encoding="utf-8")
    )
    candidate = json.loads(
        (MOCKS / "candidate_matches" / f"{case}.json").read_text(encoding="utf-8")
    )
    labels = json.loads(
        (MOCKS / "reviewed_labels" / f"{case}.json").read_text(encoding="utf-8")
    )
    return {
        "contract_version": "0.1.0",
        "judge_input_id": f"judge-input-{case}",
        "task_id": baseline["task_id"],
        "detection_id": baseline["detection_id"],
        "baseline_match_set": baseline,
        "candidate_match_set": candidate,
        "reviewed_label_set": labels,
        "criteria": {
            "minimum_attack_retention": 1.0,
            "maximum_new_benign_matches": 0,
        },
        "versions": {"contracts": "0.1.0"},
    }


def test_judge_entrypoint_loads_published_shared_input_contract():
    result = _load_run_judge()(_case_input())

    assert result["contract_version"] == "0.1.0"
    assert result["judge_input_id"] == "judge-input-case_001"
    assert result["decision"]["status"] in {"PASS", "REJECT"}


def test_missing_input_id_returns_contract_valid_inconclusive():
    judge_input = _case_input()
    judge_input.pop("judge_input_id")

    result = _load_run_judge()(judge_input)

    assert result["decision"]["status"] == "INCONCLUSIVE"
    assert any(failure["code"] == "SCHEMA" for failure in result["decision"]["failures"])


def test_zero_baseline_attack_matches_is_inconclusive():
    judge_input = _case_input()
    attack_ids = {
        item["event_id"]
        for item in judge_input["reviewed_label_set"]["labels"]
        if item["label"] == "attack"
    }
    judge_input["baseline_match_set"]["matches"] = [
        match
        for match in judge_input["baseline_match_set"]["matches"]
        if match["event_id"] not in attack_ids
    ]

    result = _load_run_judge()(judge_input)

    assert result["decision"]["status"] == "INCONCLUSIVE"
    assert any(failure["code"] == "X-7" for failure in result["decision"]["failures"])


def test_controller_adapter_invokes_deterministic_judge():
    adapter_path = REPO_ROOT / "99_integration" / "adapters" / "judge_service.py"
    spec = importlib.util.spec_from_file_location("test_judge_service_adapter", adapter_path)
    assert spec is not None and spec.loader is not None
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)

    result = adapter.build_judge_service().handle(_case_input())

    assert result.contract == "judge_result"
    assert result.payload["judge_input_id"] == "judge-input-case_001"
    assert result.payload["decision"]["status"] in {"PASS", "REJECT"}
