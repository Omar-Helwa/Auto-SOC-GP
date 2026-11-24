"""Sigma detection dict -> boolean tree -> SPL text.

Own renderer, no pySigma. Supported Sigma subset: named selections (a map, or a
list of maps = OR), list values (OR), ``contains`` / ``startswith`` /
``endswith`` / ``all`` modifiers, ``*`` wildcards, and conditions made of
and / or / not / parentheses / ``1 of x*`` / ``all of x*`` / ``1 of them`` /
``all of them``.

SPL precedence is NOT first, then OR, then AND (OR binds tighter than the
implicit AND), so every OR inside an AND is parenthesised.
"""

from __future__ import annotations

import fnmatch
import re

from ..rule_edits.sigma_match import _tokenize
from .ast import And, Leaf, Not, Or, make_and, make_not, make_or
from .errors import SplError, SplUnsupported

_SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all"}
_PLAIN_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:\-]*$")
_PLAIN_SCOPE = re.compile(r"^[A-Za-z0-9_.*:\-/+@]+$")
SCOPE_ORDER = ("index", "sourcetype", "source", "earliest", "latest")


# --------------------------------------------------------------------------- #
# Sigma -> tree
# --------------------------------------------------------------------------- #
def _leaf(field: str, mod: str | None, value) -> Leaf:
    if value is None:
        raise SplUnsupported(f"a null check on {field} has no SPL equivalent in this converter", construct="null")
    text = str(value)
    if "?" in text:
        raise SplUnsupported(f"the value {text!r} of {field} uses '?': SPL searches have no one-character wildcard",
                             construct="question_mark")
    if mod == "contains":
        text = f"*{text}*"
    elif mod == "startswith":
        text = f"{text}*"
    elif mod == "endswith":
        text = f"*{text}"
    return Leaf(field, text)


def _key_node(key: str, expected):
    field, *mods = key.split("|")
    unknown = set(mods) - _SUPPORTED_MODIFIERS
    if unknown:
        raise SplUnsupported(f"the Sigma modifier(s) {sorted(unknown)} on {field} have no SPL equivalent "
                             "in this converter", construct="|".join(sorted(unknown)))
    mod = next((m for m in mods if m != "all"), None)
    values = expected if isinstance(expected, list) else [expected]
    leaves = [_leaf(field, mod, v) for v in values]
    return make_and(leaves) if "all" in mods else make_or(leaves)


def _selection_node(sel):
    if isinstance(sel, list):
        if all(isinstance(s, dict) for s in sel):
            return make_or([_selection_node(s) for s in sel])
        raise SplUnsupported("keyword (list of strings) selections have no SPL equivalent here", construct="keywords")
    if not isinstance(sel, dict):
        raise SplUnsupported(f"a selection of type {type(sel).__name__} is not supported", construct="selection")
    if not sel:
        raise SplError("a selection is empty")
    return make_and([_key_node(k, v) for k, v in sel.items()])


class _CondParser:
    def __init__(self, tokens: list[str], detection: dict):
        self.t, self.i, self.det = tokens, 0, detection
        self.names = [k for k in detection if k != "condition"]

    def peek(self):
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def take(self) -> str:
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        node = self.or_()
        if self.i != len(self.t):
            raise SplError(f"unexpected token {self.t[self.i]!r} in the Sigma condition")
        return node

    def or_(self):
        items = [self.and_()]
        while self.peek() == "or":
            self.take()
            items.append(self.and_())
        return make_or(items)

    def and_(self):
        items = [self.not_()]
        while self.peek() == "and":
            self.take()
            items.append(self.not_())
        return make_and(items)

    def not_(self):
        if self.peek() == "not":
            self.take()
            return make_not(self.not_())
        return self.atom()

    def atom(self):
        tok = self.peek()
        if tok is None:
            raise SplError("the Sigma condition ends unexpectedly")
        if tok == "(":
            self.take()
            node = self.or_()
            if self.peek() != ")":
                raise SplError("missing ')' in the Sigma condition")
            self.take()
            return node
        if tok in ("1", "all") and self.i + 1 < len(self.t) and self.t[self.i + 1].lower() == "of":
            quant = self.take().lower()
            self.take()
            target = self.take()
            if target.lower() == "them":
                group = [n for n in self.names if not n.startswith("_")]
            else:
                group = [n for n in self.names if fnmatch.fnmatchcase(n, target)]
            if not group:
                raise SplError(f"'{quant} of {target}' matches no selection")
            nodes = [_selection_node(self.det[n]) for n in group]
            return make_or(nodes) if quant == "1" else make_and(nodes)
        name = self.take()
        if name not in self.names:
            raise SplError(f"the Sigma condition references an unknown selection {name!r}")
        return _selection_node(self.det[name])


def sigma_to_tree(detection: dict):
    condition = detection.get("condition")
    if isinstance(condition, list):
        if len(condition) != 1:
            raise SplUnsupported("several Sigma conditions are not supported", construct="multi_condition")
        condition = condition[0]
    if not isinstance(condition, str) or not condition.strip():
        raise SplError("the Sigma rule has no condition")
    if "|" in condition:
        raise SplUnsupported("aggregation / pipe in a Sigma condition has no SPL equivalent here",
                             construct="aggregation")
    try:
        tokens = _tokenize(condition)
    except Exception as exc:
        raise SplError(f"the Sigma condition cannot be read: {exc}") from exc
    return _CondParser(tokens, detection).parse()


# --------------------------------------------------------------------------- #
# Tree -> SPL
# --------------------------------------------------------------------------- #
def escape_value(value: str) -> str:
    """Escape for a double-quoted SPL value: backslash and quote. '*' stays a wildcard."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _field(name: str) -> str:
    if not _PLAIN_FIELD.match(name):
        raise SplUnsupported(f"the field name {name!r} needs quoting rules this converter does not implement",
                             construct="field_name")
    return name


def _leaf_text(leaf: Leaf) -> str:
    return f'{_field(leaf.field)}="{escape_value(leaf.pattern)}"'


def _render(node, *, top: bool) -> str:
    if isinstance(node, Leaf):
        return _leaf_text(node)
    if isinstance(node, Not):
        inner = node.item
        if isinstance(inner, Leaf):
            return f"NOT {_leaf_text(inner)}"
        return f"NOT ({_render(inner, top=False)})"
    if isinstance(node, And):
        parts = []
        for c in node.items:
            text = _render(c, top=False)
            parts.append(f"({text})" if isinstance(c, Or) else text)
        return (" " if top else " AND ").join(parts)
    if isinstance(node, Or):
        parts = []
        for c in node.items:
            text = _render(c, top=False)
            parts.append(f"({text})" if isinstance(c, And) else text)
        return " OR ".join(parts)
    raise SplError(f"unknown node {node!r}")


def render_tree(node, scope: dict[str, list[str]] | None = None) -> str:
    """Render a tree (plus optional scope) as one SPL search."""
    prefix = " ".join(_scope_terms(scope or {}))
    body = _render(node, top=True)
    if prefix and isinstance(node, Or):
        body = f"({body})"
    return f"{prefix} {body}".strip()


def _scope_value(value: str) -> str:
    return value if _PLAIN_SCOPE.match(value) else f'"{escape_value(value)}"'


def _scope_terms(scope: dict[str, list[str]]) -> list[str]:
    terms: list[str] = []
    for key in SCOPE_ORDER:
        values = scope.get(key) or []
        if not values:
            continue
        if len(values) == 1 or key in ("earliest", "latest"):
            terms.extend(f"{key}={_scope_value(v)}" for v in values)
        else:
            terms.append("(" + " OR ".join(f"{key}={_scope_value(v)}" for v in values) + ")")
    return terms
