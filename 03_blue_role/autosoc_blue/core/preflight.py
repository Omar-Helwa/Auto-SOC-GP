"""Pre-flight checks on a draft, BEFORE it goes to the platform and the judge.

1. Policy (always decidable): allowed operations and fields, edit budget, value
   limits, no exclusion built only on attacker-controllable fields (a filter on
   CommandLine alone is an evasion recipe), known false-positive ids.
2. Local preview with the injected RuleValidator: apply the edits to the Sigma
   rule, then every false positive must stop matching, every must-detect case
   must still match. If the validator cannot decide (unsupported Sigma), the
   preview is reported as unverifiable, never silently passed.

The judge stays the authority. Pre-flight only avoids spending a Splunk run on
an edit we can already see is wrong.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..ports import RuleUnverifiable, RuleValidator
from ..rule_edits.apply import CandidateRule, EditError, apply_edits
from ..schemas.models import RuleEdit
from .context import BlueContext
from .draft import Draft

MAX_VALUE_LEN = 300
MIN_VALUE_LEN = 3
MAX_VALUES = 10
MAX_CONDITIONS = 6


@dataclass(frozen=True)
class Issue:
    code: str
    message: str
    blocking: bool = True


@dataclass
class PreflightReport:
    issues: list[Issue] = field(default_factory=list)
    candidate: CandidateRule | None = None
    preview_verified: bool = False
    removed_false_positives: list[str] = field(default_factory=list)
    kept_must_detect: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(i.blocking for i in self.issues)

    def codes(self) -> list[str]:
        return [i.code for i in self.issues]

    def reasons(self) -> list[str]:
        """Blocking reasons, as short sentences (fed back to the model on retry)."""
        return [f"{i.code}: {i.message}" for i in self.issues if i.blocking]

    def summary(self) -> str:
        return "ok" if not self.issues else "; ".join(f"{i.code}: {i.message}" for i in self.issues)


def _policy_issues(ctx: BlueContext, draft: Draft, allow_partial: bool) -> list[Issue]:
    issues: list[Issue] = []
    c = ctx.constraints
    if not draft.edits:
        return [Issue("no_edits", "the proposal contains no edits")]
    if len(draft.edits) > c.max_edits:
        issues.append(Issue("too_many_edits", f"{len(draft.edits)} edits > max_edits {c.max_edits}"))
    attacker = set(c.attacker_controllable_fields)
    for n, edit in enumerate(draft.edits):
        issues += _edit_issues(n, edit, c.allowed_operations, set(c.allowed_fields), attacker, ctx)
    known = {fp.evidence_id for fp in ctx.false_positives}
    unknown = [e for e in draft.addressed_false_positives if e not in known]
    if unknown:
        issues.append(Issue("unknown_false_positive", f"not in the input: {unknown}"))
    if not draft.addressed_false_positives:
        issues.append(Issue("no_false_positive_addressed", "addressed_false_positives is empty"))
    elif not allow_partial:
        missing = sorted(known - set(draft.addressed_false_positives))
        if missing:
            issues.append(Issue("false_positive_not_addressed", f"the proposal does not address {missing}"))
    return issues


def _edit_issues(n, edit: RuleEdit, allowed_ops, allowed_fields, attacker, ctx: BlueContext) -> list[Issue]:
    issues: list[Issue] = []
    tag = f"edit {n}"
    if edit.operation not in allowed_ops:
        issues.append(Issue("operation_not_allowed", f"{tag}: operation {edit.operation!r} is not allowed"))
    if edit.operation == "narrow_selection":
        if not edit.target_selection:
            issues.append(Issue("target_selection_missing", f"{tag}: narrow_selection needs target_selection"))
        elif edit.target_selection not in ctx.selection_names:
            issues.append(Issue(
                "target_selection_unknown",
                f"{tag}: selection {edit.target_selection!r} does not exist; rule selections: {ctx.selection_names}",
            ))
    elif edit.target_selection:
        issues.append(Issue("target_selection_forbidden", f"{tag}: add_exclusion must not set target_selection"))
    if not edit.conditions:
        issues.append(Issue("no_conditions", f"{tag}: no conditions"))
    if len(edit.conditions) > MAX_CONDITIONS:
        issues.append(Issue("too_many_conditions", f"{tag}: {len(edit.conditions)} conditions > {MAX_CONDITIONS}"))
    for cond in edit.conditions:
        if cond.field not in allowed_fields:
            issues.append(Issue("field_not_allowed", f"{tag}: field {cond.field!r} is not in allowed_fields"))
        if cond.modifier not in ("equals", "contains", "startswith", "endswith"):
            issues.append(Issue("modifier_invalid", f"{tag}: modifier {cond.modifier!r}"))
        if not cond.values or len(cond.values) > MAX_VALUES:
            issues.append(Issue("values_invalid", f"{tag}: {cond.field} needs 1..{MAX_VALUES} values"))
        for v in cond.values:
            if "*" in v or "?" in v:
                issues.append(Issue("wildcard_value", f"{tag}: {cond.field} value {v!r} has a wildcard"))
            elif not MIN_VALUE_LEN <= len(v) <= MAX_VALUE_LEN:
                issues.append(Issue(
                    "value_length", f"{tag}: {cond.field} value must be {MIN_VALUE_LEN}..{MAX_VALUE_LEN} chars"))
    if edit.conditions and all(x.field in attacker for x in edit.conditions):
        code = "evadable_exclusion" if edit.operation == "add_exclusion" else "evadable_narrowing"
        issues.append(Issue(
            code,
            f"{tag}: uses only attacker-controllable fields {sorted({x.field for x in edit.conditions})}; "
            "anchor it on a field the attacker cannot set",
        ))
    return issues


def run_preflight(ctx: BlueContext, draft: Draft, validator: RuleValidator, *, allow_partial: bool = False) -> PreflightReport:
    report = PreflightReport(issues=_policy_issues(ctx, draft, allow_partial))
    if not draft.edits:
        return report
    try:
        report.candidate = apply_edits(ctx.rule_text, draft.edits)
    except EditError as exc:
        report.issues.append(Issue("edit_not_applicable", str(exc)))
        return report
    problems = validator.check(report.candidate.rule_text)
    if problems:
        report.issues.append(Issue("candidate_invalid", "; ".join(problems)))
        return report

    base_text, cand_text = ctx.rule_text, report.candidate.rule_text
    try:
        lost, unseen, kept = [], [], []
        for case in ctx.must_detect:
            base_hit = validator.matches(base_text, case.observed_fields)
            cand_hit = validator.matches(cand_text, case.observed_fields)
            if cand_hit:
                kept.append(case.evidence_id)
            if base_hit and not cand_hit:
                lost.append(case.evidence_id)
            if not base_hit:
                unseen.append(case.evidence_id)
        removed, still = [], []
        addressed = set(draft.addressed_false_positives)
        for fp in ctx.false_positives:
            if fp.evidence_id not in addressed:
                continue
            (still if validator.matches(cand_text, fp.observed_fields) else removed).append(fp.evidence_id)
    except RuleUnverifiable as exc:
        report.issues.append(Issue("preview_unverifiable", f"local matcher: {exc}", blocking=False))
        return report

    report.preview_verified = True
    report.removed_false_positives, report.kept_must_detect = removed, kept
    if lost:
        report.issues.append(Issue("would_lose_attack", f"the candidate no longer matches must-detect {lost}"))
    if still:
        report.issues.append(Issue("false_positive_not_removed", f"the candidate still matches {still}"))
    if unseen:
        report.issues.append(Issue(
            "base_rule_misses_attack",
            f"the BASE rule does not match {unseen} locally; check the case data or the matcher",
            blocking=False,
        ))
    return report
