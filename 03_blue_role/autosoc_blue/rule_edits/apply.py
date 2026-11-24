"""Apply a blue_proposal's edits to a Sigma rule, deterministically.

The LLM only PROPOSES edits (structured data). This module is the one place
that turns them into a candidate rule, so the result is reproducible and
never contains free text from the model inside the detection logic.

- ``add_exclusion``    adds a block ``filter_autosoc_<n>`` and rewrites the
  condition to ``(<old condition>) and not filter_autosoc_<n>``.
- ``narrow_selection`` adds AND-ed field conditions inside an existing
  selection. It refuses to touch filter blocks (narrowing a filter that is
  used under ``not`` would WIDEN the rule) and refuses to overwrite a key the
  selection already has.
"""

from __future__ import annotations

import copy
import difflib
from dataclasses import dataclass, field

import yaml

from ..schemas import constants
from ..schemas.models import FieldCondition, RuleEdit


class EditError(ValueError):
    """The edit cannot be applied to this rule (structural problem)."""


@dataclass
class CandidateRule:
    rule: dict
    rule_text: str
    diff: str
    filters_added: list[str] = field(default_factory=list)
    selections_narrowed: list[str] = field(default_factory=list)


def parse_rule(rule_text: str) -> dict:
    try:
        rule = yaml.safe_load(rule_text)
    except yaml.YAMLError as exc:
        raise EditError(f"rule is not valid YAML: {exc}") from exc
    if not isinstance(rule, dict) or not isinstance(rule.get("detection"), dict):
        raise EditError("rule has no 'detection' mapping")
    condition = rule["detection"].get("condition")
    if not isinstance(condition, str) or not condition.strip():
        raise EditError("rule detection has no single string 'condition'")
    return rule


def dump_rule(rule: dict) -> str:
    return yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, default_flow_style=False)


def _sigma_key(cond: FieldCondition) -> str:
    return cond.field if cond.modifier == "equals" else f"{cond.field}|{cond.modifier}"


def _block(conditions: list[FieldCondition]) -> dict:
    block: dict = {}
    for cond in conditions:
        key = _sigma_key(cond)
        if key in block:
            raise EditError(f"duplicate condition key {key!r} in one edit")
        block[key] = list(cond.values) if len(cond.values) > 1 else cond.values[0]
    return block


def _next_filter_name(detection: dict) -> str:
    n = 1
    while f"{constants.EXCLUSION_PREFIX}{n}" in detection:
        n += 1
    return f"{constants.EXCLUSION_PREFIX}{n}"


def apply_edits(rule_text: str, edits: list[RuleEdit]) -> CandidateRule:
    base = parse_rule(rule_text)
    rule = copy.deepcopy(base)
    detection = rule["detection"]
    filters_added: list[str] = []
    narrowed: list[str] = []

    for edit in edits:
        if edit.operation == "add_exclusion":
            name = _next_filter_name(detection)
            condition = detection.pop("condition")
            detection[name] = _block(edit.conditions)
            detection["condition"] = f"({condition}) and not {name}"
            filters_added.append(name)
        elif edit.operation == "narrow_selection":
            target = edit.target_selection
            if not target or target == "condition" or target not in detection:
                raise EditError(f"target_selection {target!r} does not exist in the rule")
            if target.lower().startswith("filter"):
                raise EditError(f"refusing to narrow {target!r}: narrowing a filter widens the rule")
            selection = detection[target]
            maps = selection if isinstance(selection, list) else [selection]
            if not all(isinstance(m, dict) for m in maps):
                raise EditError(f"selection {target!r} is not a field map")
            extra = _block(edit.conditions)
            for m in maps:
                clash = set(extra) & set(m)
                if clash:
                    raise EditError(f"selection {target!r} already has {sorted(clash)}")
                m.update(extra)
            narrowed.append(target)
        else:
            raise EditError(f"unknown operation {edit.operation!r}")

    old_text, new_text = dump_rule(base), dump_rule(rule)
    diff = "".join(difflib.unified_diff(
        old_text.splitlines(keepends=True), new_text.splitlines(keepends=True),
        fromfile="base_rule.yml", tofile="candidate_rule.yml",
    ))
    return CandidateRule(rule=rule, rule_text=new_text, diff=diff,
                         filters_added=filters_added, selections_narrowed=narrowed)
