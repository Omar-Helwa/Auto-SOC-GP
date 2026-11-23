# Contract: `judge_result`

| | |
|---|---|
| **Version** | `0.1.0` |
| **Consumers** | Orchestrator (stores it in the feedback record) |
| **Review owner** | Member 1 (orchestrator) |

The deterministic decision for one round. The judge builds it from the baseline and candidate
`match_set` artifacts and the `reviewed_label_set`, without any model call.

## Two shapes

| `decision.status` | Present fields |
|---|---|
| `PASS` / `REJECT` | `contract_version`, `judge_input_id`, `task_id`, `evaluation_summary`, `baseline_metrics`, `candidate_metrics`, `comparison`, `mandatory_gates`, `decision`, `provenance` |
| `INCONCLUSIVE` | `contract_version`, `judge_input_id`, `task_id`, `decision` only |

Rules the schema enforces:

- `PASS` has an empty `decision.failed_gates`; `REJECT` has at least one.
- `PASS` and `REJECT` have an empty `decision.failures`.
- `INCONCLUSIVE` has at least one entry in `decision.failures` and no failed gates, because gates were never run.
- `judge_input_id` and `task_id` may be `null` only for `INCONCLUSIVE` (unreadable input).

## `decision.failures[]`

| Field | Notes |
|---|---|
| `code` | Rule id from `validation_rules.json` (`MS-1`, `LS-1`, `LS-2`, `LS-3`, `X-1`, `X-2`, `X-4`, `X-5`, `X-6`) or a judge code: `SCHEMA`, `INPUT`, `CRITERIA`. |
| `kind` | `invalid` (contract violation) or `incomplete` (well-formed but evidence missing). |
| `message` | Human-readable detail. |

## Gates (`mandatory_gates[].gate_id`)

`attack_retention`, `new_benign_matches`, `evidence_completeness`, `execution_validity`.

## Comparison

All match lists are sorted `event_id` values in the same identity space as `match_set` and
`reviewed_label_set`: `retained`, `removed`, `added`, `lost_attack`, `removed_benign`,
`new_attack`, `new_benign`. Metric deltas are candidate minus baseline.

## Examples

- Valid PASS: [`examples/valid_judge_result_pass.json`](examples/valid_judge_result_pass.json)
- Valid REJECT: [`examples/valid_judge_result_reject.json`](examples/valid_judge_result_reject.json)
- Valid INCONCLUSIVE: [`examples/valid_judge_result_inconclusive.json`](examples/valid_judge_result_inconclusive.json)
- Invalid: [`examples/invalid_judge_result.json`](examples/invalid_judge_result.json) (status `PASS` with a failed gate, `provenance` missing)
