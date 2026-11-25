# `feedback_record` contract

`feedback_record` is the Orchestrator's immutable audit record for a round
evaluated by the deterministic Judge. It embeds the canonical `judge_result`
unchanged, along with a copy of its complete decision, pinned round versions,
and stable references to the artifacts used. It is persisted before the
Orchestrator closes the round.

The record logs the result. It does not update prompts, rule versions,
criteria, or any model automatically.

## Files

- [`feedback_record.schema.json`](feedback_record.schema.json): JSON Schema
  Draft 2020-12 definition. It references the shared Judge-result schema.
- [`examples/valid_feedback_record.json`](examples/valid_feedback_record.json):
  evaluated PASS example.
- [`examples/valid_feedback_record_inconclusive.json`](examples/valid_feedback_record_inconclusive.json):
  valid INCONCLUSIVE example.
- [`examples/invalid_feedback_record.json`](examples/invalid_feedback_record.json):
  syntactically valid JSON with an unsupported decision status.

## Producer and consumers

- **Producer:** Orchestrator, after accepting a Judge result.
- **Consumers:** feedback/audit storage and downstream reporting or analysis.
- **Lifecycle:** persist this record first, then close the round using the
  returned storage reference. PASS and REJECT close as judged outcomes;
  INCONCLUSIVE is a valid Judge outcome and closes as inconclusive, without
  fabricating an Orchestrator error.

An evaluation made inconclusive before the Judge runs because required
evidence is missing does not have a `judge_result`; it follows the
Orchestrator's pre-Judge inconclusive path and does not produce this record.

## Fields and consistency rules

- `task_id` is the `round_request.task_id`; `round_id` is the Orchestrator's
  round identifier. In Architecture 1, they are the same value.
- `decision` is an exact copy of `judge_result.decision`, including `status`,
  `reasons`, `failed_gates`, and `failures`. Status values are `PASS`, `REJECT`,
  or `INCONCLUSIVE` as defined by the Judge-result contract.
- `artifact_refs` contains stable references to the Red proposal, Platform
  evidence, reviewed labels, Blue proposal, compiled candidate rule, baseline
  and candidate match sets, and persisted Judge result. Each reference must
  resolve to the exact immutable document used in the round. Its string format
  is defined by the owning artifact store.
- `versions` copies the pinned reproducibility references from the frozen
  round configuration, including prompt, model, rule, dataset/evaluation set,
  and criteria versions.
- `judge_result` is the complete shared
  [`judge_result`](../judge_result/README.md) message, preserved unchanged.
- `recorded_at` is the UTC time the feedback record was assembled.

JSON Schema checks the shape of both decision objects but cannot require their
values to be equal. Producers must enforce semantic consistency:

1. `round_id == task_id == judge_result.task_id`.
2. Top-level `decision` exactly equals `judge_result.decision`.
3. For PASS/REJECT, `judge_result.provenance.criteria` matches the thresholds
   frozen in the round request; `versions.criteria_version` identifies the
   criteria version. Evaluation and provenance identities match the frozen
   round and referenced artifacts.
4. Artifact references resolve to documents belonging to this task, detection,
   evaluation set, and workflow.

The Judge-result schema permits a null `task_id` only for an INCONCLUSIVE
result where the input was unreadable. Such a result cannot be safely
associated with a feedback record for a specific round; the Orchestrator should
retain it for error/audit handling without emitting this feedback record.

## Versioning and ownership

Feedback-record contract version is `0.1.0`; the embedded Judge result retains
its own contract version. Changes to required feedback fields or their meaning
need a feedback contract version update and corresponding producer/consumer
migration. Judge-specific metrics, comparisons, gates, and failures are owned
by the Judge-result contract and are not redefined here.
