"""RuleValidator adapter backed by the local Sigma matcher."""

from __future__ import annotations

from functools import lru_cache
from typing import Mapping

from ..ports import RuleUnverifiable
from ..rule_edits.apply import EditError, parse_rule
from ..rule_edits.sigma_match import UnsupportedSigma, rule_matches


@lru_cache(maxsize=256)
def _parsed(rule_text: str) -> dict:
    return parse_rule(rule_text)


class LocalSigmaValidator:
    """Checks and evaluates a Sigma rule with the small deterministic matcher."""

    def check(self, rule_text: str) -> list[str]:
        try:
            _parsed(rule_text)
        except EditError as exc:
            return [str(exc)]
        return []

    def matches(self, rule_text: str, event: Mapping[str, str]) -> bool:
        try:
            return rule_matches(_parsed(rule_text)["detection"], dict(event))
        except UnsupportedSigma as exc:
            raise RuleUnverifiable(str(exc)) from exc
        except EditError as exc:
            raise RuleUnverifiable(str(exc)) from exc
