# Contract: `blue_proposal`

| | |
|---|---|
| **Version** | `0.1.0` |
| **Status** | DRAFT, pending team ratification |
| **Producer** | Blue role |
| **Consumers** | Orchestrator (Member 1), Judge (Member 4), Platform (Member 5, compiles the candidate rule) |
| **Review owner** | Blue role |

A small, bounded set of edits to one detection rule, proposed by Blue to remove observed false
positives while keeping the required attack detections. A `blue_proposal` is a **proposal only**:
it never carries Splunk matches, labels or a verdict (the judge owns those), and it can never change
the judge's acceptance criteria.

## Required fields

| Field | Type | Notes |
|-------|------|-------|
| `contract_version` | string (semver) | Must equal `0.1.0`. |
| `proposal_id` | string | Unique, UUID recommended. |
| `task_id` | string | Mirrors the blue input `task_id`. |
| `prompt_version` | string | Blue prompt template version. Flows into the audit trail. |
| `detection_under_test` | object | `{ detection_id, rule_version }`; `rule_version` is the BASE rule the edits apply to. |
| `edits` | array (1-5) | Applied in order. See below. |
| `addressed_false_positives` | array of string | `evidence_id`s from the blue input that the edits should remove. |
| `justification` | string | Why the false positives go away and the required attacks stay detected. |

## Optional fields

| Field | Type | Notes |
|-------|------|-------|
| `expected_effect` | string | A hypothesis, not a result. |
| `reference_rules` | array (≤10) | `{rule_id, title, source}` of public rules retrieved to ground the edit. |
| `evidence_references` | array | `telemetry_evidence` references only, never raw evidence. |
| `constraints_ack` | object | `within_allowed_edits`, `no_execution`, `no_verdict`, `no_judge_criteria_change`: all `true`. |
| `rationale` | string | Short reasoning. |

## Edits

| `operation` | Effect on the Sigma rule | `target_selection` |
|---|---|---|
| `add_exclusion` | New block `filter_autosoc_<n>` built from `conditions`; condition becomes `(<old>) and not filter_autosoc_<n>`. | forbidden |
| `narrow_selection` | `conditions` are AND-ed into an existing selection. | required |

Each edit has 1-6 `conditions`: `{field, modifier, values}`. `modifier` ∈ `equals`, `contains`,
`startswith`, `endswith`. `values` are OR-ed, 3-300 characters each, and **must not contain `*` or
`?`**, so an exclusion can never silently become "match everything".

## Validation rules

1. `additionalProperties: false` everywhere; unknown fields (e.g. a `judge_result`) are rejected.
2. 1-5 edits; 1-6 conditions per edit; 1-10 values per condition.
3. `narrow_selection` requires `target_selection`; `add_exclusion` forbids it.
4. No wildcards in values.
5. `contract_version` pinned to `0.1.0`; a breaking change bumps the version and notifies every consumer.

Rules that depend on the round (allowed fields, edit budget, attacker-controllable fields) live in
the blue input's `edit_constraints` and are enforced by Blue's pre-flight checks
(`03_blue_role/rule_edits/preflight.py`) before the proposal leaves Blue.

## Examples

- Valid: [`examples/valid_blue_proposal.json`](examples/valid_blue_proposal.json)
- Invalid: [`examples/invalid_blue_proposal.json`](examples/invalid_blue_proposal.json) (wildcard value, unknown operation, `narrow_selection` without a target, forbidden `judge_result` field)
