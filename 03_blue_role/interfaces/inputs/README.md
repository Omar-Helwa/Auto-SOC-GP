# Blue input contract (`blue_input`)

| | |
|---|---|
| **Version** | `0.1.0` |
| **Status** | Blue-owned, DRAFT |
| **Upstream source** | Orchestrator (Member 1), from the `round_request`, the detection under test, and verified evidence from the Platform evidence store (Member 5) |

What Blue needs to propose an edit, matching the blue context in the report ("current rule,
observed false-positive evidence, attack cases that must remain detected, relevant prior blue
edits, permitted edit schema").

## Required fields

| Field | Type | Notes |
|-------|------|-------|
| `contract_version` | string | `0.1.0`. |
| `task_id` | string | Echoed into the proposal and any error. |
| `prompt_version` | string | Blue prompt version pinned for the round. |
| `output_contract_version` | string | `blue_proposal` version to emit (`0.1.0`). |
| `detection` | object | `detection_id`, `rule_version`, `rule_format` (`sigma`), `rule_text` (Sigma YAML), `logic_summary` (+ optional `attack_techniques`). |
| `false_positives` | array (1-50) | Reviewed benign events the rule matched. |
| `must_detect` | array (1-200) | Reviewed attack events that must still match after the edit. |
| `edit_constraints` | object | `allowed_operations`, `allowed_fields`, `max_edits` (1-5), optional `attacker_controllable_fields`. |

Optional: `prior_blue_edits` (≤10 judged outcomes: `proposal_id`, `decision`, `summary`, `failure_reason`).

Each case in `false_positives` / `must_detect` is `{evidence_reference, observed_fields, label_note?}`.
`observed_fields` is a flat `field -> value` map copied by the Platform from **verified** telemetry.
It is **untrusted text**: Blue treats it as data, never as instructions.

## Why Blue sees field values and not only references

Red only cites evidence. Blue has to write an exclusion such as `User = CORP\svc_inventory`, so it
needs the values. The values still come from the platform evidence store, never from a model.

## Validation rules

1. `additionalProperties: false`; unknown fields are rejected.
2. Missing required field → `error_response` category `missing_information`.
3. Wrong type / out-of-enum / out-of-range → `error_response` category `validation`.

## Examples

- Valid: [`examples/valid_blue_input.json`](examples/valid_blue_input.json)
- Invalid: [`examples/invalid_blue_input.json`](examples/invalid_blue_input.json) (empty `must_detect`, `rule_format` not `sigma`, `max_edits` 9)
