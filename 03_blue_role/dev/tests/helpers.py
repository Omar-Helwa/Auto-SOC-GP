"""Small helpers shared by the Blue tests."""

from __future__ import annotations

from autosoc_blue.adapters.validators import LocalSigmaValidator
from autosoc_blue.core.context import build_context
from autosoc_blue.rule_edits import apply_edits
from autosoc_blue.schemas.models import BlueInput, BlueProposal


def context_for(blue_input: dict):
    return build_context(BlueInput.from_dict(blue_input))


def check_effect(blue_input: dict, proposal: dict) -> tuple[list[str], list[str]]:
    """Apply a proposal to the rule; return (false positives still matched, attacks no longer matched)."""
    inp = BlueInput.from_dict(blue_input)
    cand = apply_edits(inp.detection.rule_text, BlueProposal.from_dict(proposal).edits)
    v = LocalSigmaValidator()
    still_fp = [c.evidence_id for c in inp.false_positives if v.matches(cand.rule_text, c.observed_fields)]
    lost = [c.evidence_id for c in inp.must_detect if not v.matches(cand.rule_text, c.observed_fields)]
    return still_fp, lost
