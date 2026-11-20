"""Build the minimum red-only context from a validated red_input (Epic D).

Isolation by construction: this builder reads ONLY from the RedInput it is
given. It never pulls in other rounds, other roles' internals, or any evidence
beyond the input's `permitted_evidence_refs`. The resulting RedContext is a pure
function of the input, so the same input always yields the same context.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from schemas.models import RedInput
from scenarios.families import describe_families


@dataclass(frozen=True)
class RedContext:
    task_id: str
    detection_id: str
    rule_version: str
    detection_summary: str
    allowed_families: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    max_workflow_steps: int
    families_block: str                 # rendered description of allowed families
    forbidden_notes: tuple[str, ...] = ()
    permitted_evidence_refs: tuple[dict, ...] = ()
    output_contract_version: str = "0.1.0"
    prompt_version: str = ""


def build_context(red_input: RedInput) -> RedContext:
    c = red_input.benign_constraints
    families = tuple(c.allowed_scenario_families)
    return RedContext(
        task_id=red_input.task_id,
        detection_id=red_input.detection.detection_id,
        rule_version=red_input.detection.rule_version,
        detection_summary=red_input.detection.logic_summary,
        allowed_families=families,
        allowed_actions=tuple(c.allowed_actions),
        max_workflow_steps=c.max_workflow_steps,
        families_block=describe_families(list(families)),
        forbidden_notes=tuple(c.forbidden_notes or ()),
        permitted_evidence_refs=tuple(e.to_dict() for e in red_input.permitted_evidence_refs),
        output_contract_version=red_input.output_contract_version,
        prompt_version=red_input.prompt_version,
    )
