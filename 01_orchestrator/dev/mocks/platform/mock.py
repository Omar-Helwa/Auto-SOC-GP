"""Platform mock for verified telemetry, execution, and dataset evidence."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from workflow import BlueInputContext, WorkflowStepOutput

from ..common import clone, load_shared_example


class MockPlatform:
    def __init__(self):
        self.verify_calls = 0
        self.candidate_execution_calls = 0

    def collect_telemetry(
        self, round_request: Mapping[str, Any], red_proposal: Mapping[str, Any]
    ) -> WorkflowStepOutput:
        task_id = round_request["task_id"]
        return WorkflowStepOutput(
            raw_output_ref=f"mock://telemetry/{task_id}",
            raw_output={"source": "mock-platform", "task_id": task_id, "red_proposal_id": red_proposal["proposal_id"]},
            detail="mock telemetry collection completed",
        )

    def verify_evidence(
        self, round_request: Mapping[str, Any], red_proposal: Mapping[str, Any], telemetry_ref: str
    ) -> WorkflowStepOutput:
        self.verify_calls += 1
        task_id = round_request["task_id"]
        if not telemetry_ref.startswith("mock://telemetry/"):
            raise ValueError("Mock evidence verifier received a non-mock telemetry reference")

        telemetry = {
            "contract_version": "0.1.0",
            "evidence_id": f"evidence-{task_id}",
            "task_id": task_id,
            "proposal_id": red_proposal["proposal_id"],
            "detection_id": round_request["detection"]["detection_id"],
            "source": "splunk",
            "execution": {
                "execution_id": f"exec-telemetry-{task_id}",
                "status": "succeeded",
                "operation_id": f"op-telemetry-{task_id}",
                "approval_id": f"approval-telemetry-{task_id}",
                "started_at": "2026-01-01T00:00:00Z",
                "completed_at": "2026-01-01T00:00:01Z",
                "event_count": 0,
                "truncated": False,
            },
            "events": [],
        }
        telemetry["content_sha256"] = hashlib.sha256(
            json.dumps(
                telemetry,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        labels = clone(load_shared_example(
            "telemetry_evidence", "valid_reviewed_label_set.json"
        ))
        dataset = round_request["dataset"]
        labels["dataset"].update({
            name: dataset[name]
            for name in ("dataset_id", "dataset_version", "evaluation_set_id", "evaluation_set_checksum")
            if name in dataset
        })

        candidate = clone(load_shared_example("candidate_rule", "valid_match_set.json"))
        candidate["task_id"] = task_id
        candidate["detection_id"] = round_request["detection"]["detection_id"]
        candidate["role"] = "candidate"
        candidate["candidate_ref"] = "cand-rule-0001"
        candidate["rule_version"] = "1.0.1-cand1"
        candidate["dataset"].update({
            name: dataset[name]
            for name in ("dataset_id", "dataset_version", "evaluation_set_id", "evaluation_set_checksum")
            if name in dataset
        })
        baseline = clone(candidate)
        baseline["match_set_id"] = f"baseline-{task_id}"
        baseline["role"] = "baseline"
        baseline["rule_version"] = round_request["detection"]["rule_version"]
        baseline.pop("candidate_ref", None)
        baseline["matches"] = [{"event_id": "evt-0007", "index": "lab_eval"}]
        baseline["execution"]["execution_id"] = f"exec-baseline-{task_id}"
        return WorkflowStepOutput(
            messages={
                "telemetry_evidence": telemetry,
                "reviewed_label_set": labels,
                "baseline_match_set": baseline,
            },
            raw_output={"telemetry_ref": telemetry_ref, "verified": True},
            detail=f"mock evidence verification #{self.verify_calls}",
        )

    def build_blue_context(
        self, round_request: Mapping[str, Any], artifacts: Mapping[str, Mapping[str, Any]]
    ) -> BlueInputContext:
        task_id = round_request["task_id"]
        detection = round_request["detection"]
        labels = artifacts["reviewed_label_set"]["labels"]
        by_id = {label["event_id"]: label for label in labels}
        false_positive = by_id["evt-0042"]
        attack = by_id["evt-0007"]
        evidence_view = {
            "task_id": task_id,
            "detection_id": detection["detection_id"],
            "false_positives": [{
                "evidence_reference": {
                    "evidence_id": false_positive["event_id"],
                    "evidence_type": "reviewed_label",
                },
                "observed_fields": {"User": "CORP\\svc_inventory", "Image": "powershell.exe"},
            }],
            "must_detect": [{
                "evidence_reference": {
                    "evidence_id": attack["event_id"],
                    "evidence_type": "reviewed_label",
                },
                "observed_fields": {"Image": "powershell.exe", "CommandLine": "-EncodedCommand"},
            }],
        }
        blue_detection = {
            "detection_id": detection["detection_id"],
            "rule_version": detection["rule_version"],
            "rule_format": "sigma",
            "rule_text": "title: Mock encoded PowerShell detection\nlogsource:\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\\\powershell.exe'\n  condition: selection\n",
            "logic_summary": detection["logic_summary"],
        }
        edit_constraints = {
            "allowed_operations": ["add_exclusion", "narrow_selection"],
            "allowed_fields": ["User", "ParentImage"],
            "attacker_controllable_fields": ["CommandLine"],
            "max_edits": 2,
        }
        return BlueInputContext(
            evidence_view=evidence_view,
            edit_constraints=edit_constraints,
            blue_detection=blue_detection,
        )

    def execute_candidate(
        self,
        round_request: Mapping[str, Any],
        blue_proposal: Mapping[str, Any],
        baseline_match_set: Mapping[str, Any] | None,
    ) -> WorkflowStepOutput:
        self.candidate_execution_calls += 1
        task_id = round_request["task_id"]
        candidate_rule = clone(load_shared_example("candidate_rule", "valid_candidate_rule.json"))
        candidate_rule.update({
            "task_id": task_id,
            "proposal_id": blue_proposal["proposal_id"],
            "detection_id": round_request["detection"]["detection_id"],
            "base_rule_version": round_request["detection"]["rule_version"],
        })
        candidate = clone(load_shared_example("candidate_rule", "valid_match_set.json"))
        candidate.update({
            "task_id": task_id,
            "match_set_id": f"candidate-{task_id}",
            "role": "candidate",
            "detection_id": round_request["detection"]["detection_id"],
            "rule_version": candidate_rule["candidate_rule_version"],
            "candidate_ref": candidate_rule["candidate_id"],
        })
        candidate["dataset"].update({
            name: round_request["dataset"][name]
            for name in ("dataset_id", "dataset_version", "evaluation_set_id", "evaluation_set_checksum")
            if name in round_request["dataset"]
        })
        candidate["execution"]["execution_id"] = f"exec-candidate-{task_id}"
        candidate["matches"] = [
            {"event_id": "evt-0007", "index": "lab_eval"},
            {"event_id": "evt-0042", "index": "lab_eval"},
        ]
        messages = {"candidate_rule": candidate_rule, "candidate_match_set": candidate}
        if baseline_match_set is None:
            raise ValueError("Mock Platform expects baseline evidence from verify_evidence")
        return WorkflowStepOutput(
            messages=messages,
            raw_output={"candidate_execution": candidate["execution"]["execution_id"]},
            detail="mock candidate execution completed",
        )
