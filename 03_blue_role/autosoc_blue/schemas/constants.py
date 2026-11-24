"""Closed vocabularies shared across the Blue component.

These mirror the ``enum`` lists in the JSON Schema contracts so the rule-edit
engine, prompt builder and models can reference them by name. A drift test
(``test_constants_match_schema``) asserts they stay identical to the schemas,
so the schemas remain the single source of truth.
"""

from __future__ import annotations

BLUE_PROPOSAL_VERSION = "0.1.0"
BLUE_INPUT_VERSION = "0.1.0"
ERROR_RESPONSE_VERSION = "0.1.0"

SOURCE_COMPONENT = "03_blue_role"

# rule_edit.operation
EDIT_OPERATIONS = ("add_exclusion", "narrow_selection")

# field_condition.modifier  (maps 1:1 to Sigma value modifiers; "equals" = no modifier)
CONDITION_MODIFIERS = ("equals", "contains", "startswith", "endswith")

# detection.rule_format
RULE_FORMATS = ("sigma",)

# prior_blue_edits[].decision
PRIOR_DECISIONS = ("accepted", "rejected", "inconclusive")

# evidence_reference.evidence_type
EVIDENCE_TYPES = ("splunk_result", "reviewed_label", "telemetry")

# error_response.category
ERROR_CATEGORIES = ("validation", "missing_information", "dependency", "timeout", "internal")

# Bounds (blue_proposal "small edit" guarantee).
MIN_EDITS = 1
MAX_EDITS = 5
MAX_CONDITIONS_PER_EDIT = 6

# Prefix for filter blocks created by add_exclusion, so a human (and the judge
# report) can always tell which parts of a rule were written by Blue.
EXCLUSION_PREFIX = "filter_autosoc_"

RETRYABLE_BY_CATEGORY = {
    "validation": False,
    "missing_information": False,
    "dependency": True,
    "timeout": True,
    "internal": False,
}
