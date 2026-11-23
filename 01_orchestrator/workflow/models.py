"""Typed values passed between the workflow and injected component services."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional


@dataclass(frozen=True)
class WorkflowStepOutput:
    """Component output before the interface adapter validates and persists it.

    ``messages`` maps the orchestrator artifact names (for example
    ``candidate_rule``) to the corresponding shared contract payloads.
    ``raw_output_ref`` identifies external execution data where no shared
    contract artifact exists, especially the telemetry collection step.
    """

    messages: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    raw_output_ref: Optional[str] = None
    # Original component response when its adapter exposes it. When omitted,
    # the workflow preserves the returned contract message(s) in the audit log.
    raw_output: Any = None
    model_id: Optional[str] = None
    detail: str = ""


@dataclass(frozen=True)
class WorkflowInvocation:
    """Prepared component call with its exact input snapshot and callable."""

    component: str
    input_payload: Mapping[str, Any]
    invoke: Callable[[], Any]
    input_artifact_refs: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class BlueInputContext:
    """Platform-provided projection needed to construct the published Blue input."""

    evidence_view: Mapping[str, Any]
    edit_constraints: Mapping[str, Any]
    blue_detection: Optional[Mapping[str, Any]] = None
    prior_blue_edits: Optional[list[Mapping[str, Any]]] = None


@dataclass(frozen=True)
class WorkflowResult:
    """Snapshot returned when a round reaches a terminal state."""

    round_id: str
    state: str
    record: Any

    @property
    def completed(self) -> bool:
        return self.state == "completed"

