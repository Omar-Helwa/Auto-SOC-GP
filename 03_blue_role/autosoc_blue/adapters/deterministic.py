"""Deterministic baseline proposer: no AI, no network, same answer every time.

It works from the evidence in the blue_input only:

1. ``add_exclusion`` (preferred). For each false positive it builds an exclusion
   from that event's own ``observed_fields`` using ``equals`` conditions, on
   fields that are allowed and NOT attacker-controllable. Every must-detect
   event has to FAIL at least one condition, so none of them can be excluded.
   It picks the smallest set of conditions that achieves this, then adds one
   more safe condition (when one exists) so the exclusion is as narrow as
   practical (identity AND process lineage, not one weak signal).
   Attacker-controllable fields (CommandLine, ...) are only used as extra
   conditions, never alone, and only when the safe fields cannot separate the
   attack events.
2. ``narrow_selection`` (fallback, only when exclusion cannot work). Adds a
   positive condition to a selection, using the values seen in the must-detect
   events. This can overfit to the observed attacks, so it is used last and
   flagged in the rationale.
"""

from __future__ import annotations

from itertools import combinations
from typing import Sequence

from ..core.context import BlueContext
from ..core.draft import Draft
from ..ports import ProposerError
from ..rule_edits.sigma_match import _value_matches
from ..schemas.models import FieldCondition, ObservedCase, RuleEdit

# Lower = preferred when several fields can do the same job.
_FIELD_PRIORITY = {"User": 0, "ParentImage": 1, "OriginalFileName": 2, "IntegrityLevel": 3, "Image": 4}
MAX_CONDITIONS_SAFE = 3
TARGET_CONDITIONS = 2
MAX_VALUE_LEN = 300
MIN_VALUE_LEN = 3


def _cond_matches(event: dict[str, str], cond: FieldCondition) -> bool:
    if cond.field not in event:
        return False
    modifier = None if cond.modifier == "equals" else cond.modifier
    return any(_value_matches(event[cond.field], v, modifier) for v in cond.values)


def _conj_matches(event: dict[str, str], conds: Sequence[FieldCondition]) -> bool:
    return all(_cond_matches(event, c) for c in conds)


def _usable(value: str) -> bool:
    return MIN_VALUE_LEN <= len(value) <= MAX_VALUE_LEN and "*" not in value and "?" not in value


def _priority(field_name: str) -> int:
    return _FIELD_PRIORITY.get(field_name, 5)


class DeterministicProposer:
    name = "deterministic"
    uses_feedback = False

    # ------------------------------------------------------------------ #
    def propose(self, ctx: BlueContext, feedback: Sequence[str] = ()) -> Draft:
        c = ctx.constraints
        exclusions: list[tuple[list[FieldCondition], list[ObservedCase]]] = []
        unresolved: list[ObservedCase] = []
        covered: set[str] = set()

        if "add_exclusion" in c.allowed_operations:
            for fp in ctx.false_positives:
                if any(_conj_matches(fp.observed_fields, conds) for conds, _ in exclusions):
                    covered.add(fp.evidence_id)
                    for conds, cases in exclusions:
                        if _conj_matches(fp.observed_fields, conds):
                            cases.append(fp)
                            break
                    continue
                conds = self._exclusion_for(ctx, fp)
                if conds is None:
                    unresolved.append(fp)
                else:
                    exclusions.append((conds, [fp]))
                    covered.add(fp.evidence_id)
            exclusions = self._merge(ctx, exclusions)
        else:
            unresolved = list(ctx.false_positives)

        edits: list[RuleEdit] = []
        addressed: list[str] = []
        notes: list[str] = []

        # Keep the edits that cover the most false positives if the budget is tight.
        exclusions.sort(key=lambda item: -len(item[1]))
        budget = c.max_edits
        for conds, cases in exclusions:
            if len(edits) >= budget:
                unresolved += cases
                continue
            ids = [fp.evidence_id for fp in cases]
            edits.append(RuleEdit("add_exclusion", conds, self._exclusion_reason(conds, ids)))
            addressed += ids

        if unresolved and len(edits) < budget and "narrow_selection" in c.allowed_operations:
            narrow = self._narrow_for(ctx, unresolved)
            if narrow is not None:
                edit, ids = narrow
                edits.append(edit)
                addressed += ids
                notes.append(
                    "narrow_selection was used because no exclusion could separate the remaining false "
                    "positives from the attacks; it keeps only the attack values seen so far, so the judge "
                    "should check it against unseen attacks."
                )

        if not edits:
            raise ProposerError(
                "no safe edit found: the false positives cannot be separated from the must-detect "
                "events using the allowed fields and operations"
            )
        left = [fp.evidence_id for fp in ctx.false_positives if fp.evidence_id not in addressed]
        if left:
            notes.append(f"No safe edit found for {left} within the allowed edits.")
        return Draft(
            edits=edits,
            addressed_false_positives=addressed,
            justification=self._justification(ctx, edits, addressed),
            rationale=" ".join(notes) or None,
            source=self.name,
        )

    # ------------------------------------------------------------------ #
    def _exclusion_for(self, ctx: BlueContext, fp: ObservedCase) -> list[FieldCondition] | None:
        allowed = set(ctx.constraints.allowed_fields)
        attacker = set(ctx.constraints.attacker_controllable_fields)
        musts = [m.observed_fields for m in ctx.must_detect]

        def atoms(fields_ok):
            out = []
            for name, value in sorted(fp.observed_fields.items()):
                if name in allowed and fields_ok(name) and _usable(value):
                    out.append(FieldCondition(name, "equals", [value]))
            return out

        safe = atoms(lambda n: n not in attacker)
        risky = atoms(lambda n: n in attacker)

        def kills(cond: FieldCondition) -> frozenset[int]:
            return frozenset(i for i, ev in enumerate(musts) if not _cond_matches(ev, cond))

        everything = frozenset(range(len(musts)))

        def best_cover(pool: list[FieldCondition], must_include_safe: bool) -> list[FieldCondition] | None:
            for size in range(1, min(MAX_CONDITIONS_SAFE, len(pool)) + 1):
                found = []
                for combo in combinations(pool, size):
                    if must_include_safe and not any(x in safe for x in combo):
                        continue
                    if frozenset().union(*(kills(x) for x in combo)) == everything:
                        found.append(combo)
                if found:
                    found.sort(key=lambda cb: (sum(_priority(x.field) for x in cb), [x.field for x in cb]))
                    return list(found[0])
            return None

        chosen = best_cover(safe, False)
        if chosen is None:
            chosen = best_cover(safe + risky, True)
        if chosen is None:
            return None
        # Make it as narrow as practical: top up with other safe conditions.
        extra = sorted((x for x in safe if x not in chosen), key=lambda x: (_priority(x.field), x.field))
        while len(chosen) < TARGET_CONDITIONS and extra:
            chosen.append(extra.pop(0))
        chosen.sort(key=lambda x: (_priority(x.field), x.field))
        return chosen

    def _merge(self, ctx: BlueContext, exclusions):
        """Join exclusions that use the same fields, when that stays safe."""
        merged: list[tuple[list[FieldCondition], list[ObservedCase]]] = []
        musts = [m.observed_fields for m in ctx.must_detect]
        for conds, cases in exclusions:
            for m_conds, m_cases in merged:
                if [(x.field, x.modifier) for x in m_conds] != [(x.field, x.modifier) for x in conds]:
                    continue
                union = [
                    FieldCondition(a.field, a.modifier, list(dict.fromkeys([*a.values, *b.values])))
                    for a, b in zip(m_conds, conds)
                ]
                if any(len(u.values) > 10 for u in union):
                    continue
                if any(_conj_matches(ev, union) for ev in musts):
                    continue  # the cross product would hide an attack
                m_conds[:] = union
                m_cases.extend(cases)
                break
            else:
                merged.append((list(conds), list(cases)))
        return merged

    def _narrow_for(self, ctx: BlueContext, fps: list[ObservedCase]):
        c = ctx.constraints
        attacker = set(c.attacker_controllable_fields)
        det = ctx.rule["detection"]
        target = None
        for name in ctx.selection_names:
            if name.lower().startswith("filter"):
                continue
            sel = det[name]
            maps = sel if isinstance(sel, list) else [sel]
            if all(isinstance(m, dict) for m in maps):
                target = (name, maps)
                break
        if target is None:
            return None
        name, maps = target
        used = {k.split("|")[0] for m in maps for k in m}
        candidates = []
        for fld in c.allowed_fields:
            if fld in attacker or fld in used:
                continue
            if not all(fld in m.observed_fields for m in ctx.must_detect):
                continue
            values = list(dict.fromkeys(m.observed_fields[fld] for m in ctx.must_detect))
            if len(values) > 10 or not all(_usable(v) for v in values):
                continue
            # Listing one value per attack event is just a copy of the attacks (overfitting):
            # only accept a field whose attack values really converge.
            if len(ctx.must_detect) >= 2 and len(values) == len(ctx.must_detect):
                continue
            lowered = {v.lower() for v in values}
            if any(fld not in fp.observed_fields or fp.observed_fields[fld].lower() in lowered for fp in fps):
                continue
            candidates.append((len(values), _priority(fld), fld, values))
        if not candidates:
            return None
        _, _, fld, values = min(candidates)
        edit = RuleEdit(
            "narrow_selection",
            [FieldCondition(fld, "equals", values)],
            f"Require {fld} to be one of the values seen in the reviewed attack events; "
            "the false positives have a different value.",
            target_selection=name,
        )
        return edit, [fp.evidence_id for fp in fps]

    # ------------------------------------------------------------------ #
    @staticmethod
    def _describe(conds: Sequence[FieldCondition]) -> str:
        return " AND ".join(f"{c.field} = {' or '.join(c.values)}" for c in conds)

    def _exclusion_reason(self, conds, ids) -> str:
        return (
            f"Exclude events where {self._describe(conds)}. This matches the reviewed false positive(s) "
            f"{', '.join(ids)}, and each must-detect event fails at least one of these conditions."
        )

    def _justification(self, ctx: BlueContext, edits: list[RuleEdit], addressed: list[str]) -> str:
        parts = []
        for e in edits:
            if e.operation == "add_exclusion":
                parts.append(
                    f"Exclusion on {self._describe(e.conditions)}: none of the {len(ctx.must_detect)} "
                    "must-detect events satisfies all of these conditions, so they keep matching")
            else:
                parts.append(
                    f"Narrowing of {e.target_selection} on {self._describe(e.conditions)}: "
                    "every must-detect event has one of these values, the false positives do not")
        attacker = set(ctx.constraints.attacker_controllable_fields)
        used_attacker = sorted({c.field for e in edits for c in e.conditions if c.field in attacker})
        tail = (
            "using allowed fields the attacker does not control."
            if not used_attacker else
            f"anchored on non-attacker fields; {', '.join(used_attacker)} is attacker-controllable and only "
            "narrows the exclusion further because no other field separates the attacks."
        )
        return (
            f"{'; '.join(parts)}. Built from the observed fields of the reviewed events "
            f"(false positives {', '.join(addressed)}), {tail}"
        )
