"""Compatibility alias: ``rule_edits`` is now ``autosoc_blue.rule_edits``."""

import sys

from autosoc_blue import rule_edits as _real
from autosoc_blue.rule_edits import apply, sigma_match  # noqa: F401

sys.modules["rule_edits.apply"] = apply
sys.modules["rule_edits.sigma_match"] = sigma_match
sys.modules[__name__] = _real
