"""Blue mock that emits the published blue_proposal contract."""

from __future__ import annotations

from typing import Any, Mapping

from ..common import clone, load_shared_example


class MockBlueRole:
    def run(self, blue_input: Mapping[str, Any]) -> dict[str, Any]:
        proposal = clone(load_shared_example("blue_proposal", "valid_blue_proposal.json"))
        proposal["task_id"] = blue_input["task_id"]
        proposal["prompt_version"] = blue_input["prompt_version"]
        proposal["detection_under_test"] = {
            "detection_id": blue_input["detection"]["detection_id"],
            "rule_version": blue_input["detection"]["rule_version"],
        }
        return proposal
