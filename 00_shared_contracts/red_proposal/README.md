# Contract: `red_proposal`

| | |
|---|---|
| **Version** | `0.1.0` |
| **Status** | DRAFT — pending team ratification |
| **Producer** | Red role (Member 2) |
| **Consumers** | Orchestrator (Member 1), Platform (Member 5, for validation/execution) |
| **Review owner** | Omar — Red role |

Defines the single bounded benign workflow variation returned by the Red role. A `red_proposal`
is a **proposal only**. It must never carry execution results, Splunk matches, reviewed labels,
or any pass/reject verdict — those belong to Platform and the Judge.

## Required fields

| Field | Type | Notes |
|-------|------|-------|
| `contract_version` | string (semver) | Must equal `0.1.0`. |
| `proposal_id` | string | Unique, UUID recommended. |
| `task_id` | string | Links back to the round; mirrors the red input `task_id`. |
| `prompt_version` | string | Red prompt template version used. Flows into the audit trail. |
| `detection_under_test` | object | `{ detection_id, rule_version }`. |
| `scenario` | object | `family`, `title`, `description`, `workflow_steps` (+ optional `expected_signal`). |
| `benign_justification` | string | Why the workflow is legitimate activity. |

## Optional fields

| Field | Type | Notes |
|-------|------|-------|
| `evidence_references` | array | References to `telemetry_evidence` only. Never raw evidence. |
| `constraints_ack` | object | `within_allowed_families`, `no_execution`, `no_verdict` — all must be `true`. |
| `rationale` | string | Short reasoning for the probe. |

## Allowed values

- `scenario.family` ∈ `admin_automation`, `software_deployment`, `it_maintenance`,
  `developer_activity`, `power_user_tooling`, `backup_and_recovery`, `security_tooling`.
- `workflow_steps[].action` ∈ `process_execution`, `file_operation`, `network_connection`,
  `registry_operation`, `scheduled_task`, `script_execution`, `account_operation`, `service_operation`.

## Validation rules

1. `additionalProperties: false` everywhere — unknown fields are rejected (keeps mocks honest).
2. `workflow_steps` must contain **1–10** items (the "bounded" guarantee).
3. `scenario.family` and every `action` must be in-enum, or the proposal is rejected locally.
4. No field may describe an execution outcome. `expected_signal` is an explicit hypothesis, not a result.
5. `contract_version` is pinned to `0.1.0`; a breaking change requires a new version folder/id.

## Examples

- Valid: [`examples/valid_red_proposal.json`](examples/valid_red_proposal.json)
- Invalid: [`examples/invalid_red_proposal.json`](examples/invalid_red_proposal.json) (out-of-enum family, 0 steps, forbidden `results` field)

## Backward-compatibility note

Changes within a sprint must stay backward compatible; otherwise bump to `0.2.0` and notify every
consumer (Team change rule). This file is a DRAFT proposed by the Red role and is open for team review.
