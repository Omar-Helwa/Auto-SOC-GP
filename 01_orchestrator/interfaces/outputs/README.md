# Orchestrator outputs

`OrchestratorOutputAdapter` builds validated component inputs and the final
feedback record from the frozen request and stored artifacts.

## Builders

| Method | When to call | Result |
|---|---|---|
| `build_red_input(round_id)` | After opening a round | Red input from frozen config; executable rule text is excluded. |
| `build_blue_input(round_id, evidence_view, edit_constraints, ...)` | After evidence verification | Blue input with reviewed cases and an explicit, version-matched rule representation. |
| `build_judge_input(round_id)` | After candidate execution | Shared `judge_input` bundle after evidence is reloaded and cross-checked. |
| `build_feedback_record(round_id)` | After accepting a Judge result | Shared feedback record with decision, pinned versions, and artifact references. |
| `complete_round(round_id)` | After `JUDGED` | Persists feedback, then closes the round according to the Judge status. |

## Blue input

Blue accepts `rule_format: sigma` and `rule_format: spl`. The Platform's
trusted rule-view adapter must supply a supported format, rule text, and
detection ID/version matching the frozen request. The builder does not
implicitly convert or relabel SPL. The Platform supplies edit constraints.

## Judge input and feedback

`build_judge_input` emits the published `00_shared_contracts/judge_input`
shape. It preserves the nested baseline/candidate `match_set` and
`reviewed_label_set` contracts and includes the frozen thresholds and version
metadata. The deterministic Judge validates this bundle and returns the shared
`judge_result`.

The input adapter checks task identity and criteria version and validates
Judge output against the shared result schema. Cross-contract evidence checks
ensure the result is tied to compatible stored artifacts. A Judge result with
no task identity cannot be associated with a round feedback record.

For a round-associated result, `complete_round` stores the shared
`feedback_record` before transitioning to `COMPLETED` for PASS/REJECT or
`INCONCLUSIVE` for an inconclusive decision. It does not change prompts, rule
versions, or criteria. Use `workflow.outputs.feedback_store` to retrieve the
record and linked artifacts; only PASS is marked retrieval-eligible.
