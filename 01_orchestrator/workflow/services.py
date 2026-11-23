"""Protocols describing services the workflow invokes.

Implementations are supplied by the application composition root. Keeping
them injectable avoids coupling round management to role or database clients.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from .models import BlueInputContext, WorkflowStepOutput


class RedService(Protocol):
    def run(self, red_input: Mapping[str, Any]) -> Mapping[str, Any] | WorkflowStepOutput: ...


class BlueService(Protocol):
    def run(self, blue_input: Mapping[str, Any]) -> Mapping[str, Any] | WorkflowStepOutput: ...


class PlatformService(Protocol):
    def collect_telemetry(self, round_request: Mapping[str, Any], red_proposal: Mapping[str, Any]) -> WorkflowStepOutput: ...

    def verify_evidence(
        self, round_request: Mapping[str, Any], red_proposal: Mapping[str, Any], telemetry_ref: str
    ) -> WorkflowStepOutput: ...

    def build_blue_context(
        self, round_request: Mapping[str, Any], artifacts: Mapping[str, Mapping[str, Any]]
    ) -> BlueInputContext: ...

    def execute_candidate(
        self,
        round_request: Mapping[str, Any],
        blue_proposal: Mapping[str, Any],
        baseline_match_set: Mapping[str, Any] | None,
    ) -> WorkflowStepOutput: ...


class JudgeService(Protocol):
    def run(self, judge_input: Mapping[str, Any]) -> Mapping[str, Any] | WorkflowStepOutput: ...


class WorkflowServices(Protocol):
    """Services required to execute one complete round."""

    red: RedService
    platform: PlatformService
    blue: BlueService
    judge: JudgeService

