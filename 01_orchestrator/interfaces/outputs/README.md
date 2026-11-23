# Orchestrator outputs

`OrchestratorOutputAdapter` builds validated component inputs and the final
feedback record from the frozen round request and stored contract artifacts.
The caller or `RoundWorkflow` sends each built input to its recipient.

## Builders

| Method | When to call | Result |
|---|---|---|
| `build_red_input(round_id)` | After opening a round | Red input derived from frozen config; executable rule text is excluded. The input is saved and audited. |
| `build_blue_input(round_id, evidence_view, edit_constraints, ...)` | After evidence verification | Blue input with reviewed case projections and a rule representation validated against Blue's input schema. |
| `build_judge_input(round_id)` | After candidate execution | Temporary local Judge bundle after stored evidence is reloaded and cross-checked. |
| `build_feedback_record(round_id)` | After accepting a Judge result | Shared feedback record with the Judge result, pinned versions, and artifact references. |
| `complete_round(round_id)` | After `JUDGED` | Saves feedback first, then closes the round using its returned reference and Judge decision. |

## Blue input

The current `round_request.detection` uses `rule_language: splunk_spl`, while
the Blue input schema requires Sigma YAML and `rule_format: sigma`. Supply an
approved Sigma representation whose detection ID and rule version match the
frozen request. The builder refuses to convert or relabel SPL. The caller also
supplies `edit_constraints`; their policy source/version is not currently
frozen in `round_request`.

## Judge input gap

There is no shared Judge-input contract yet, so `build_judge_input` validates a
temporary Orchestrator envelope. It preserves the shared `match_set` and
`reviewed_label_set` documents under `baseline_match_set`,
`candidate_match_set`, and `reviewed_label_set`, and includes frozen criteria
and version metadata.

The deterministic Judge's current validator expects `evaluation_set`,
`baseline`, `candidate`, `reviewed_labels`, and `provenance`. It also requires
fields not present in the current shared artifact shape, including the full
evaluation event inventory and per-match evidence references. The Judge
criteria property names differ too. Consequently, this builder's output is
not yet a valid input to the real Judge. Agree on the canonical input and a
lossless mapping before connecting it; the dev mock only accepts the local
Orchestrator shape.

## Judge result and feedback

The input adapter validates returned `judge_result` messages against the
published shared schema. It checks task identity when supplied and, for
PASS/REJECT, checks the criteria version. It does not yet verify every
provenance identity against the stored artifacts. A Judge INCONCLUSIVE result
with a null task ID (used when the Judge cannot read its input) must be retained
for audit/error handling rather than associated with a round feedback record;
that case needs explicit handling.

For a round-associated Judge result, `complete_round` stores a shared
`feedback_record` before transitioning the manager to `COMPLETED` for
PASS/REJECT or `INCONCLUSIVE` for an inconclusive decision. It does not change
prompts, rule versions, or criteria. Use `workflow.outputs.feedback_store` to
retrieve the record and its linked source artifacts; only PASS is marked
retrieval-eligible by that read-time hint.

The temporary schemas and their status are listed in
[`../contracts/README.md`](../contracts/README.md).
