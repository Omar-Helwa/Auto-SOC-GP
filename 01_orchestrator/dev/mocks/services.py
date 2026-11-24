"""Compose contract-shaped services for a complete mock round."""

from __future__ import annotations

from types import SimpleNamespace

from .blue_role import MockBlueRole
from .judge import MockJudge
from .platform import MockPlatform
from .red_role import MockRedRole


class MockWorkflowServices(SimpleNamespace):
    """No external model, Judge, Platform, or Splunk dependency is used."""

    def __init__(self, scenario: str = "pass"):
        supported = {
            "pass", "reject", "inconclusive", "malformed_output",
            "retry_exhaustion", "timeout", "partial_persistence_failure",
        }
        if scenario not in supported:
            raise ValueError(f"Unsupported mock scenario: {scenario!r}")
        decision = {"reject": "REJECT", "inconclusive": "INCONCLUSIVE"}.get(scenario, "PASS")
        super().__init__(
            red=MockRedRole(scenario),
            blue=MockBlueRole(),
            judge=MockJudge(decision),
            platform=MockPlatform(),
        )
        self.scenario = scenario
