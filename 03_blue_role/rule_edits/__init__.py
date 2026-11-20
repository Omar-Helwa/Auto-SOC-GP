"""Blue role: deterministic rule editing.

- ``apply`` : turn structured edits into a candidate Sigma rule + diff.
"""

from .apply import CandidateRule, EditError, apply_edits, parse_rule  # noqa: F401
