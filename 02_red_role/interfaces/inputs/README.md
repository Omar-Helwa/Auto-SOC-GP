# Red input contract (`red_input`)

| | |
|---|---|
| **Version** | `0.1.0` |
| **Status** | Red-owned (Member 2) |
| **Owner** | Omar — Red role |
| **Upstream source** | Derived from the shared `round_request` contract (Member 1) + detection/constraints |

This is what the Red component accepts at its public boundary. It is red-owned: red decides what
it needs to produce a proposal and validates it on entry. The orchestrator is responsible for
populating these fields from the `round_request` and the detection under test.

## Required fields

| Field | Type | Notes |
|-------|------|-------|
| `contract_version` | string (semver) | `0.1.0`. |
| `task_id` | string | Echoed into the proposal and any error. |
| `detection` | object | `detection_id`, `rule_version`, `logic_summary` (+ optional `description`). |
| `benign_constraints` | object | `allowed_scenario_families`, `max_workflow_steps` (1–10), `allowed_actions` (+ optional `forbidden_notes`). |
| `prompt_version` | string | Red prompt template version pinned for the round. |
| `output_contract_version` | string (semver) | Which `red_proposal` version to emit (`0.1.0`). |

## Optional fields

| Field | Type | Notes |
|-------|------|-------|
| `permitted_evidence_refs` | array | Evidence references red may use as context. References only. |

## Validation rules

1. `additionalProperties: false` — unknown fields rejected.
2. Missing a required field → red returns an `error_response` with category `missing_information`.
3. Malformed types/out-of-enum values → `error_response` with category `validation`.
4. `max_workflow_steps` is clamped to the contract's hard ceiling of 10 (see `red_proposal`).
5. `allowed_scenario_families` and `allowed_actions` are the whitelist the context builder and the
   scenario bounds checker enforce downstream — red never proposes outside them.

## Examples

- Valid: [`examples/valid_red_input.json`](examples/valid_red_input.json)
- Invalid: [`examples/invalid_red_input.json`](examples/invalid_red_input.json) (missing `detection.logic_summary`, empty `allowed_actions`)

> Consumes the shared `round_request` contract. If `round_request` field names change, update the
> mapping here and notify Member 1.
