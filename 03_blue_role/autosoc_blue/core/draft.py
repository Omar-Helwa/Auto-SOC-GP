"""A Draft is what a proposer returns: edits plus the text around them."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..schemas.models import RuleEdit


@dataclass
class Draft:
    edits: list[RuleEdit]
    addressed_false_positives: list[str] = field(default_factory=list)
    justification: str = ""
    expected_effect: str | None = None
    rationale: str | None = None
    source: str = "unknown"  # which proposer made it
