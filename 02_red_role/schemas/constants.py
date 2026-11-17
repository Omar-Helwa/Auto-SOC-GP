"""Closed vocabularies shared across the Red component.

These mirror the ``enum`` lists in the JSON Schema contracts. They are kept
here as Python constants so the prompt builder, scenario bounds checker, and
models can reference them by name. A drift test
(``test_constants_match_schema``) asserts they stay identical to the schema,
so the schema remains the single source of truth.
"""

from __future__ import annotations

# Pinned contract versions (see 00_shared_contracts/*/*.schema.json).
RED_PROPOSAL_VERSION = "0.1.0"
RED_INPUT_VERSION = "0.1.0"
ERROR_RESPONSE_VERSION = "0.1.0"

SOURCE_COMPONENT = "02_red_role"

# scenario.family  (red_proposal + red_input)
SCENARIO_FAMILIES = (
    "admin_automation",
    "software_deployment",
    "it_maintenance",
    "developer_activity",
    "power_user_tooling",
    "backup_and_recovery",
    "security_tooling",
)

# workflow_step.action
WORKFLOW_ACTIONS = (
    "process_execution",
    "file_operation",
    "network_connection",
    "registry_operation",
    "scheduled_task",
    "script_execution",
    "account_operation",
    "service_operation",
)

# evidence_reference.evidence_type
EVIDENCE_TYPES = (
    "splunk_result",
    "reviewed_label",
    "telemetry",
)

# error_response.category
ERROR_CATEGORIES = (
    "validation",
    "missing_information",
    "dependency",
    "timeout",
    "internal",
)

# Hard bound on scenario.workflow_steps (red_proposal "bounded" guarantee).
MIN_WORKFLOW_STEPS = 1
MAX_WORKFLOW_STEPS = 10

# Default retry semantics per error category (see error_response README).
RETRYABLE_BY_CATEGORY = {
    "validation": False,
    "missing_information": False,
    "dependency": True,
    "timeout": True,
    "internal": False,
}
