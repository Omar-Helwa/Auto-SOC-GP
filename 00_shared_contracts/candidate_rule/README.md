# Contract: `candidate_rule` — candidate rule artifact and match set

| | |
|---|---|
| **Producer** | Platform (Member 5) |
| **Consumers** | Judge (Member 4), Orchestrator (Member 1) |
| **Proposed by** | Orchestrator (Member 1) |
| **Version** | `0.1.0` |
| **Status** | DRAFT — pending review by Platform (Member 5) and Judge (Member 4) |

This folder holds two schemas that together carry "the compiled candidate rule and its matches"
(Data Flow, step 5):

- [`candidate_rule.schema.json`](candidate_rule.schema.json) — the validated, compiled candidate rule.
- [`match_set.schema.json`](match_set.schema.json) — the events matched by one rule on the frozen
  evaluation set. The same schema is used for the **baseline** (`role: baseline`) and the
  **candidate** (`role: candidate`).

Neither schema contains labels, metrics, or a verdict. The judge decides from measured evidence.

## `candidate_rule` fields

| Field | Type | Notes |
|-------|------|-------|
| `contract_version` | string (required) | `0.1.0`. |
| `candidate_id` | string (required) | Unique id. This is what `match_set.candidate_ref` points to. |
| `task_id` | string (required) | Round/task identifier. |
| `proposal_id` | string (required) | `proposal_id` of the `blue_proposal` this was built from. |
| `detection_id` | string (required) | Detection under test. |
| `base_rule_version` | string (required) | Must equal the baseline match set's `rule_version`. |
| `candidate_rule_version` | string (required) | Must equal the candidate match set's `rule_version`. |
| `applied_edit_count` | integer 1..5 (optional) | Number of blue edits applied. |
| `compiled_rule` | object (required) | `language` (`splunk_spl`), `text` (the exact search), `sha256` (hash of `text`). |
| `validation` | object (required) | `status` must be `passed`; optional `checks[]` and `validated_at`. |
| `evidence_reference` | object (optional) | Reference to stored evidence (see `telemetry_evidence`). |

A rejected proposal never becomes a `candidate_rule`; it is reported as an `error_response`.

## `match_set` fields

| Field | Type | Notes |
|-------|------|-------|
| `contract_version` | string (required) | `0.1.0`. |
| `match_set_id` | string (required) | Unique id. |
| `task_id` | string (required) | Shared by the baseline and candidate sets of one round. |
| `role` | enum (required) | `baseline` or `candidate`. |
| `detection_id` | string (required) | Detection under test. |
| `rule_version` | string (required) | Version of the rule that was executed. |
| `candidate_ref` | string (conditional) | `candidate_id` of the candidate rule. Required for `candidate`, forbidden for `baseline`. |
| `dataset` | object (required) | `dataset_id`, `dataset_version`, `evaluation_set_id` (the frozen set), optional `evaluation_set_checksum`. |
| `execution` | object (required) | `execution_id`, `status` (`completed`, `partial`, `failed`, `timeout`), optional `search_ref`, timestamps, `events_scanned`, `errors[]`. |
| `matches` | array (required) | One entry per matched event: `event_id` (required), optional `index`, `sourcetype`, `event_time`, `splunk_ref`. |
| `evidence_reference` | object (optional) | Reference to the stored execution evidence. |

## Rules

1. Matches are compared by `event_id`, never by counts. `event_id` must be deterministic and identical
   across the baseline run, the candidate run, and the reviewed labels.
2. Baseline and candidate must use the same frozen `evaluation_set_id`; otherwise the result is incomplete.
3. `execution.status` other than `completed` means incomplete evidence (the judge returns `inconclusive`).
4. Checks JSON Schema cannot express (unique `event_id`, hash of the compiled text, cross-file
   agreement) are listed in [`../validation_rules.json`](../validation_rules.json): MS-1, CR-1, X-1 to X-5.
5. `$ref`s use `$id` URIs (`autosoc://contracts/...`); a validator needs a registry of all schemas.

## Examples

- Valid: [`examples/valid_candidate_rule.json`](examples/valid_candidate_rule.json),
  [`examples/valid_match_set.json`](examples/valid_match_set.json)
- Invalid: [`examples/invalid_candidate_rule.json`](examples/invalid_candidate_rule.json),
  [`examples/invalid_match_set.json`](examples/invalid_match_set.json) (reasons in `_why_invalid`)