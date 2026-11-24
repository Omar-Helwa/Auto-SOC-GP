"""Deterministic Sigma rule editing and the small local matcher.

- ``apply``       : turn structured edits into a candidate Sigma rule + diff.
- ``sigma_match`` : local, deterministic Sigma matcher for pre-flight checks.
"""

from .apply import CandidateRule, EditError, apply_edits, parse_rule  # noqa: F401
from .sigma_match import UnsupportedSigma, rule_matches, selection_matches  # noqa: F401
