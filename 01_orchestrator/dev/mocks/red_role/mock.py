"""Red mock that emits the published red_proposal contract."""

from __future__ import annotations

import time
from typing import Any, Mapping

from workflow import WorkflowServiceError

from ..common import clone, load_shared_example


class MockRedRole:
    def __init__(self, scenario: str = "pass"):
        self.scenario = scenario
        self.calls = 0

    def run(self, red_input: Mapping[str, Any]) -> dict[str, Any]:
        self.calls += 1
        if self.scenario == "retry_exhaustion":
            raise WorkflowServiceError(
                "Mock Red dependency is unavailable", category="dependency", retryable=True
            )
        if self.scenario == "timeout":
            time.sleep(1.2)
        if self.scenario == "malformed_output":
            return {"task_id": red_input["task_id"], "unexpected": True}

        proposal = clone(load_shared_example("red_proposal", "valid_red_proposal.json"))
        proposal["task_id"] = red_input["task_id"]
        proposal["prompt_version"] = red_input["prompt_version"]
        proposal["detection_under_test"] = {
            "detection_id": red_input["detection"]["detection_id"],
            "rule_version": red_input["detection"]["rule_version"],
        }
        return proposal
