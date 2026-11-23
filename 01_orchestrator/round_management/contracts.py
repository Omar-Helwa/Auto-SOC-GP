"""Values mirrored from the shared contracts in ``00_shared_contracts``.

Round management has no third-party dependencies, so it cannot load the JSON
Schemas at runtime. These constants copy the allowed values instead, and the
contract tests (``dev/tests``) compare them with the schema files so any drift
is caught.
"""

import re

CONTRACT_VERSION = "0.1.0"
SOURCE_COMPONENT = "01_orchestrator"

# error_response.category
ERROR_CATEGORIES = ("validation", "missing_information", "dependency", "timeout", "internal")

# red_input.benign_constraints / red_proposal.scenario.family
SCENARIO_FAMILIES = (
    "admin_automation",
    "software_deployment",
    "it_maintenance",
    "developer_activity",
    "power_user_tooling",
    "backup_and_recovery",
    "security_tooling",
)
ALLOWED_ACTIONS = (
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
EVIDENCE_TYPES = ("splunk_result", "reviewed_label", "telemetry")

# round_request.detection.rule_language / candidate_rule.compiled_rule.language
RULE_LANGUAGES = ("splunk_spl",)

# round_request.task_id. It is also the round id and a file name, so it is path-safe.
TASK_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
SHA256_PATTERN = re.compile(r"^[A-Fa-f0-9]{64}$")

# Decisions a judge_result can carry.
JUDGE_DECISIONS = ("pass", "reject", "inconclusive")

# Names under which a round records references to the contract messages it received.
RED_PROPOSAL = "red_proposal"
TELEMETRY_EVIDENCE = "telemetry_evidence"
REVIEWED_LABEL_SET = "reviewed_label_set"
BLUE_PROPOSAL = "blue_proposal"
CANDIDATE_RULE = "candidate_rule"
BASELINE_MATCH_SET = "baseline_match_set"
CANDIDATE_MATCH_SET = "candidate_match_set"
JUDGE_RESULT = "judge_result"
FEEDBACK_RECORD = "feedback_record"

KNOWN_ARTIFACTS = frozenset(
    {
        RED_PROPOSAL,
        TELEMETRY_EVIDENCE,
        REVIEWED_LABEL_SET,
        BLUE_PROPOSAL,
        CANDIDATE_RULE,
        BASELINE_MATCH_SET,
        CANDIDATE_MATCH_SET,
        JUDGE_RESULT,
        FEEDBACK_RECORD,
    }
)

# round_request.detection maximum lengths (red_input.detection uses the first two as well).
MAX_DESCRIPTION_LENGTH = 1000
MAX_LOGIC_SUMMARY_LENGTH = 4000
MAX_RULE_TEXT_LENGTH = 20000
