"""SPL <-> Sigma conversion for the supported subset.

``spl_to_sigma_rule``  SPL search -> Sigma rule dict (the internal model). The
                       index/sourcetype/source/earliest/latest scope is kept
                       under the ``x_spl_scope`` key, not as detection logic.
``sigma_rule_to_spl``  Sigma rule dict -> SPL text (scope key re-emitted).
``convert_text``       text in, text out, for the CLI and HTTP ``convert``.
"""

from __future__ import annotations

import re

import yaml

from .ast import And, Leaf, Not, Or
from .errors import SplError, SplUnsupported
from .parser import SplSearch, parse_spl
from .render import render_tree, sigma_to_tree

SCOPE_KEY = "x_spl_scope"


# --------------------------------------------------------------------------- #
# SPL -> Sigma
# --------------------------------------------------------------------------- #
def _leaf_to_sigma(leaf: Leaf) -> tuple[str, str]:
    """(modifier, value) for an SPL pattern: '*x*' contains, 'x*' startswith, '*x' endswith."""
    p = leaf.pattern
    lead, trail = p.startswith("*"), p.endswith("*") and len(p) > 1
    core = p[1:] if lead else p
    core = core[:-1] if trail else core
    if not core or "*" in core:  # '*' alone (field exists) or a wildcard in the middle: keep the raw pattern
        return "equals", p
    if lead and trail:
        return "contains", core
    if lead:
        return "endswith", core
    if trail:
        return "startswith", core
    return "equals", p


def _key(field: str, mod: str) -> str:
    return field if mod == "equals" else f"{field}|{mod}"


def _selection_for(leaves: list[Leaf]):
    pairs = [(_leaf_to_sigma(lf), lf.field) for lf in leaves]
    mods = {m for (m, _), _f in pairs}
    field = leaves[0].field
    if len(mods) == 1:
        mod = next(iter(mods))
        values = list(dict.fromkeys(v for (_, v), _f in pairs))
        return {_key(field, mod): values if len(values) > 1 else values[0]}
    return [{_key(field, m): v} for (m, v), _f in pairs]


def _group(node) -> list[Leaf] | None:
    """A leaf, or an OR of leaves on one field, is one Sigma selection."""
    if isinstance(node, Leaf):
        return [node]
    if isinstance(node, Or) and all(isinstance(c, Leaf) for c in node.items) and \
            len({c.field for c in node.items}) == 1:
        return list(node.items)
    return None


class _Builder:
    def __init__(self) -> None:
        self.detection: dict = {}

    def _name(self, field: str, negated: bool) -> str:
        base = ("filter_" if negated else "sel_") + (re.sub(r"\W+", "_", field).strip("_").lower() or "x")
        name, n = base, 2
        while name in self.detection:
            name, n = f"{base}_{n}", n + 1
        return name

    def build(self, node, negated: bool) -> tuple[str, str]:
        """Return (condition text, kind) with kind in atom / and / or."""
        group = _group(node)
        if group is not None:
            name = self._name(group[0].field, negated)
            self.detection[name] = _selection_for(group)
            return name, "atom"
        if isinstance(node, Not):
            text, kind = self.build(node.item, not negated)
            return (f"not ({text})" if kind != "atom" else f"not {text}"), "atom"
        word = " and " if isinstance(node, And) else " or "
        kind = "and" if isinstance(node, And) else "or"
        parts = []
        for child in node.items:
            text, ckind = self.build(child, negated)
            parts.append(f"({text})" if ckind in ("and", "or") and ckind != kind else text)
        return word.join(parts), kind


def spl_to_sigma_rule(
    spl: str,
    *,
    title: str = "SPL search",
    rule_id: str | None = None,
    allow_preserved_pipeline: bool = False,
) -> tuple[dict, list[str]]:
    """Parse a Splunk search and return (Sigma rule dict, notes)."""
    search: SplSearch = parse_spl(
        spl, allow_preserved_pipeline=allow_preserved_pipeline
    )
    builder = _Builder()
    condition, _ = builder.build(search.node, False)
    detection = dict(builder.detection)
    detection["condition"] = condition
    rule: dict = {"title": title}
    if rule_id:
        rule["id"] = rule_id
    if search.scope:
        rule[SCOPE_KEY] = {k: list(v) for k, v in search.scope.items()}
    rule["detection"] = detection
    return rule, search.notes


# --------------------------------------------------------------------------- #
# Sigma -> SPL
# --------------------------------------------------------------------------- #
def sigma_rule_to_spl(rule: dict, *, index: str | None = None) -> str:
    if not isinstance(rule, dict) or not isinstance(rule.get("detection"), dict):
        raise SplError("the rule has no 'detection' mapping")
    scope = {k: list(v) for k, v in (rule.get(SCOPE_KEY) or {}).items()}
    if index:
        scope["index"] = [index]
    return render_tree(sigma_to_tree(rule["detection"]), scope)


def describe_conditions(rule: dict) -> str:
    """Plain-text view of the normalised selections and condition (for the LLM prompt)."""
    det = rule["detection"]
    lines = []
    for name, sel in det.items():
        if name == "condition":
            continue
        maps = sel if isinstance(sel, list) else [sel]
        rendered = []
        for m in maps:
            rendered.append(" AND ".join(
                f"{k.split('|')[0]} {(k.split('|') + ['equals'])[1] if '|' in k else 'equals'} "
                f"{v if isinstance(v, list) else [v]}" for k, v in m.items()))
        lines.append(f"- {name}: " + "  OR  ".join(rendered))
    lines.append(f"- condition: {det.get('condition')}")
    scope = rule.get(SCOPE_KEY)
    if scope:
        lines.append(f"- scope (not detection logic): {scope}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Text in, text out
# --------------------------------------------------------------------------- #
def convert_text(text: str, src: str, dst: str, *, index: str | None = None) -> tuple[str, list[str]]:
    """Convert a rule between ``sigma`` (YAML) and ``spl``. Returns (text, notes)."""
    if src == dst:
        raise SplError("the source and target formats are the same")
    if (src, dst) == ("sigma", "spl"):
        from ..rule_edits.apply import EditError, parse_rule

        try:
            rule = parse_rule(text)
        except EditError as exc:
            raise SplError(str(exc)) from exc
        return sigma_rule_to_spl(rule, index=index), []
    if (src, dst) == ("spl", "sigma"):
        from ..rule_edits.apply import dump_rule

        rule, notes = spl_to_sigma_rule(text)
        return dump_rule(rule), notes
    raise SplError(f"unsupported conversion {src} -> {dst} (use sigma<->spl)")


__all__ = ["SplError", "SplUnsupported", "convert_text", "describe_conditions", "sigma_rule_to_spl",
           "spl_to_sigma_rule", "yaml"]
