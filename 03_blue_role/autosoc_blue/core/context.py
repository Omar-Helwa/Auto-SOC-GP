"""Build the Blue-only context from a validated blue_input."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from ..ports import EvidenceSource
from ..rule_edits.apply import parse_rule
from ..schemas.models import BlueInput, ObservedCase


@dataclass
class BlueContext:
    input: BlueInput
    rule: dict
    notes: list[str] = field(default_factory=list)

    @property
    def false_positives(self) -> list[ObservedCase]:
        return self.input.false_positives

    @property
    def must_detect(self) -> list[ObservedCase]:
        return self.input.must_detect

    @property
    def constraints(self):
        return self.input.edit_constraints

    @property
    def rule_text(self) -> str:
        return self.input.detection.rule_text

    @property
    def selection_names(self) -> list[str]:
        return [k for k in self.rule["detection"] if k != "condition"]


def build_context(inp: BlueInput, evidence: EvidenceSource | None = None) -> BlueContext:
    """Parse the rule and (optionally) enrich cases with extra fields by reference.

    Enrichment only ADDS fields that are missing; it never changes a field the
    platform already supplied.
    """
    rule = parse_rule(inp.detection.rule_text)
    notes: list[str] = []
    if evidence is not None:
        for case in [*inp.false_positives, *inp.must_detect]:
            try:
                extra: Mapping[str, str] | None = evidence.fetch(case.evidence_id)
            except Exception as exc:  # an optional source must never break a round
                notes.append(f"evidence source failed for {case.evidence_id}: {exc}")
                continue
            if not extra:
                continue
            for key, value in extra.items():
                if key not in case.observed_fields and isinstance(value, str):
                    case.observed_fields[key] = value
    return BlueContext(input=inp, rule=rule, notes=notes)
