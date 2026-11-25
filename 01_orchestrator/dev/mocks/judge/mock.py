"""Judge mock that emits published pass, reject, or inconclusive results."""

from __future__ import annotations

from typing import Any, Mapping

from ..common import clone, load_shared_example


class MockJudge:
    def __init__(self, decision: str = "PASS"):
        if decision not in {"PASS", "REJECT", "INCONCLUSIVE"}:
            raise ValueError(f"Unsupported mock Judge decision: {decision!r}")
        self.decision = decision

    def run(self, judge_input: Mapping[str, Any]) -> dict[str, Any]:
        filenames = {
            "PASS": "valid_judge_result_pass.json",
            "REJECT": "valid_judge_result_reject.json",
            "INCONCLUSIVE": "valid_judge_result_inconclusive.json",
        }
        result = clone(load_shared_example("judge_result", filenames[self.decision]))
        result["task_id"] = judge_input["task_id"]
        result["judge_input_id"] = f"judge-input-{judge_input['task_id']}"
        if self.decision in {"PASS", "REJECT"}:
            summary = result["evaluation_summary"]
            summary.update({
                "detection_id": judge_input["detection_id"],
                "dataset_id": judge_input["candidate_match_set"]["dataset"]["dataset_id"],
                "dataset_version": judge_input["candidate_match_set"]["dataset"]["dataset_version"],
                "evaluation_set_id": judge_input["candidate_match_set"]["dataset"]["evaluation_set_id"],
                "baseline_rule_version": judge_input["baseline_match_set"]["rule_version"],
                "candidate_rule_version": judge_input["candidate_match_set"]["rule_version"],
            })
            result["provenance"]["baseline_match_set_id"] = judge_input["baseline_match_set"]["match_set_id"]
            result["provenance"]["candidate_match_set_id"] = judge_input["candidate_match_set"]["match_set_id"]
            result["provenance"]["baseline_execution_id"] = judge_input["baseline_match_set"]["execution"]["execution_id"]
            result["provenance"]["candidate_execution_id"] = judge_input["candidate_match_set"]["execution"]["execution_id"]
            result["provenance"]["candidate_ref"] = judge_input["candidate_match_set"]["candidate_ref"]
            result["provenance"]["label_set_id"] = judge_input["reviewed_label_set"]["label_set_id"]
            result["provenance"]["label_set_version"] = judge_input["reviewed_label_set"]["label_set_version"]
            result["provenance"]["criteria"] = dict(judge_input["criteria"])
            result["provenance"]["contract_versions"] = {
                "match_set": judge_input["candidate_match_set"]["contract_version"],
                "reviewed_label_set": judge_input["reviewed_label_set"]["contract_version"],
            }
        return result
