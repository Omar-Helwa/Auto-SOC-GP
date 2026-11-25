"""Adapt the deterministic Judge to the shared controller Service interface."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from shared_services.controller.services import CallableService, ServiceResult

REPO_ROOT = Path(__file__).resolve().parents[2]
JUDGE_ROOT = REPO_ROOT / "04_deterministic_judge"
JUDGE_INPUT_MODULE = "autosoc_deterministic_judge_input"


def _load_run_judge():
    loaded_module = sys.modules.get(JUDGE_INPUT_MODULE)
    if loaded_module is not None:
        return loaded_module.run_judge

    judge_root = str(JUDGE_ROOT)
    if judge_root not in sys.path:
        sys.path.append(judge_root)

    module_path = JUDGE_ROOT / "interfaces" / "inputs" / "judge_input.py"
    spec = importlib.util.spec_from_file_location(JUDGE_INPUT_MODULE, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load deterministic Judge from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.run_judge


def build_judge_service() -> CallableService:
    run_judge = _load_run_judge()

    def handle(payload: dict) -> ServiceResult:
        return ServiceResult("judge_result", run_judge(payload))

    return CallableService(handle)
