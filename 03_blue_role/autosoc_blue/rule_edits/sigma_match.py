"""A small, deterministic Sigma matcher for LOCAL pre-checks only.

It evaluates a Sigma ``detection`` block against one event given as a flat
``{field: value}`` dict. Supported: named selections (a map, or a list of
maps = OR), list values (OR), the ``contains`` / ``startswith`` / ``endswith``
/ ``all`` modifiers, ``*`` and ``?`` wildcards, case-insensitive comparison,
and conditions built from ``and`` / ``or`` / ``not`` / parentheses /
``1 of name*`` / ``all of name*`` / ``1 of them`` / ``all of them``.

This is NOT the judge. The judge runs the compiled rule in Splunk on the
frozen evaluation set; this matcher only lets Blue reject obviously bad edits
before spending a Splunk run. Anything it cannot evaluate raises
``UnsupportedSigma`` so the caller can mark the check "unverifiable" instead
of guessing.
"""

from __future__ import annotations

import fnmatch
import re


class UnsupportedSigma(Exception):
    """The rule uses a Sigma feature this local matcher does not implement."""


_SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all"}


def _value_matches(event_value: str, pattern: str, modifier: str | None) -> bool:
    ev = event_value.lower()
    pat = str(pattern).lower()
    if modifier == "contains":
        pat = f"*{pat}*"
    elif modifier == "startswith":
        pat = f"{pat}*"
    elif modifier == "endswith":
        pat = f"*{pat}"
    if "*" in pat or "?" in pat:
        # fnmatch also treats [...] specially; escape it so only * and ? are wildcards.
        regex = fnmatch.translate(pat.replace("[", "[[]"))
        return re.match(regex, ev, re.DOTALL) is not None
    return ev == pat


def _key_matches(event: dict[str, str], key: str, expected) -> bool:
    field, *mods = key.split("|")
    unknown = set(mods) - _SUPPORTED_MODIFIERS
    if unknown:
        raise UnsupportedSigma(f"modifier(s) {sorted(unknown)} on {field}")
    require_all = "all" in mods
    modifier = next((m for m in mods if m != "all"), None)
    values = expected if isinstance(expected, list) else [expected]
    if field not in event:
        # A missing field never matches a value (Sigma 'null' checks are not supported).
        if any(v is None for v in values):
            raise UnsupportedSigma(f"null check on {field}")
        return False
    hits = [_value_matches(event[field], v, modifier) for v in values]
    return all(hits) if require_all else any(hits)


def selection_matches(event: dict[str, str], selection) -> bool:
    if isinstance(selection, list):
        if all(isinstance(s, dict) for s in selection):
            return any(selection_matches(event, s) for s in selection)
        raise UnsupportedSigma("keyword (list of strings) selections")
    if not isinstance(selection, dict):
        raise UnsupportedSigma(f"selection of type {type(selection).__name__}")
    return all(_key_matches(event, k, v) for k, v in selection.items())


# --------------------------------------------------------------------------- #
# Condition parsing
# --------------------------------------------------------------------------- #
_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokenize(condition: str) -> list[str]:
    pos, out = 0, []
    condition = condition.strip()
    while pos < len(condition):
        m = _TOKEN.match(condition, pos)
        if not m:
            raise UnsupportedSigma(f"condition syntax near {condition[pos:]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


class _Parser:
    """Recursive descent: or_expr := and_expr ('or' and_expr)*, and so on."""

    def __init__(self, tokens: list[str], names: list[str], evaluate):
        self.t, self.i, self.names, self.evaluate = tokens, 0, names, evaluate

    def _peek(self) -> str | None:
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def _take(self) -> str:
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self) -> bool:
        value = self._or()
        if self.i != len(self.t):
            raise UnsupportedSigma(f"unexpected token {self.t[self.i]!r}")
        return value

    def _or(self) -> bool:
        value = self._and()
        while self._peek() == "or":
            self._take()
            rhs = self._and()
            value = value or rhs
        return value

    def _and(self) -> bool:
        value = self._not()
        while self._peek() == "and":
            self._take()
            rhs = self._not()
            value = value and rhs
        return value

    def _not(self) -> bool:
        if self._peek() == "not":
            self._take()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        tok = self._peek()
        if tok is None:
            raise UnsupportedSigma("condition ends unexpectedly")
        if tok == "(":
            self._take()
            value = self._or()
            if self._peek() != ")":
                raise UnsupportedSigma("missing ')'")
            self._take()
            return value
        if tok in ("1", "all") and self.i + 1 < len(self.t) and self.t[self.i + 1].lower() == "of":
            quantifier = self._take().lower()
            self._take()  # 'of'
            target = self._take()
            if target.lower() == "them":
                group = [n for n in self.names if not n.startswith("_")]
            else:
                group = [n for n in self.names if fnmatch.fnmatchcase(n, target)]
            if not group:
                raise UnsupportedSigma(f"'{quantifier} of {target}' matches no selection")
            results = [self.evaluate(n) for n in group]
            return any(results) if quantifier == "1" else all(results)
        name = self._take()
        if name not in self.names:
            raise UnsupportedSigma(f"condition references unknown selection {name!r}")
        return self.evaluate(name)


def rule_matches(detection: dict, event: dict[str, str]) -> bool:
    """True if the Sigma ``detection`` block matches ``event``."""
    condition = detection.get("condition")
    if isinstance(condition, list):
        if len(condition) != 1:
            raise UnsupportedSigma("multiple conditions")
        condition = condition[0]
    if not isinstance(condition, str):
        raise UnsupportedSigma("missing condition")
    if "|" in condition:
        raise UnsupportedSigma("aggregation / pipe in condition")
    names = [k for k in detection if k != "condition"]
    cache: dict[str, bool] = {}

    def evaluate(name: str) -> bool:
        if name not in cache:
            cache[name] = selection_matches(event, detection[name])
        return cache[name]

    return _Parser(_tokenize(condition), names, evaluate).parse()
