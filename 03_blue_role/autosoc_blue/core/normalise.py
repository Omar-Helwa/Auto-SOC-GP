"""Clean a proposer's draft before pre-flight.

Only mechanical tidying: strip text, drop duplicates, clip long strings, drop
keys that do not belong. Normalising never invents a condition and never makes
an edit broader.
"""

from __future__ import annotations

from ..schemas.models import FieldCondition, RuleEdit
from .context import BlueContext
from .draft import Draft

REASON_MAX = 500
JUSTIFICATION_MAX = 2000
EFFECT_MAX = 500


def _clip(text: str | None, limit: int) -> str | None:
    if text is None:
        return None
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def _dedupe(values: list) -> list[str]:
    seen, out = set(), []
    for v in values:
        v = str(v).strip()
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def normalise(draft: Draft, ctx: BlueContext) -> Draft:
    edits: list[RuleEdit] = []
    seen = set()
    for edit in draft.edits:
        operation = str(edit.operation).strip().lower()
        conditions = [
            FieldCondition(str(c.field).strip(), str(c.modifier).strip().lower(), _dedupe(list(c.values)))
            for c in edit.conditions
        ]
        target = (edit.target_selection or "").strip() or None
        if operation != "narrow_selection":
            target = None
        key = (operation, target, tuple((c.field, c.modifier, tuple(c.values)) for c in conditions))
        if key in seen:
            continue
        seen.add(key)
        edits.append(RuleEdit(operation, conditions, _clip(edit.reason, REASON_MAX) or "Edit proposed by Blue.", target))

    known = [fp.evidence_id for fp in ctx.false_positives]
    addressed = _dedupe(list(draft.addressed_false_positives))  # unknown ids stay: pre-flight reports them
    if not addressed:
        addressed = list(known)  # the proposer did not say: assume it targets all of them
    return Draft(
        edits=edits,
        addressed_false_positives=addressed,
        justification=_clip(draft.justification, JUSTIFICATION_MAX) or "",
        expected_effect=_clip(draft.expected_effect, EFFECT_MAX),
        rationale=_clip(draft.rationale, JUSTIFICATION_MAX),
        source=draft.source,
    )
