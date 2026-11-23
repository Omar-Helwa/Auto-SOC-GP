# Inputs accepted by the orchestrator

`OrchestratorInputAdapter` is the inbound boundary between contract messages,
the artifact store, and `RoundManager`. It does not call component services.
`RoundWorkflow` invokes injected services and submits their results here; an
application can also use the adapter directly for a controlled integration.

## API and round lifecycle

```python
from interfaces.inputs import OrchestratorInputAdapter

incoming = OrchestratorInputAdapter(manager, artifacts)
record = incoming.open_round(round_request)
incoming.begin_attempt(record.round_id)
# invoke the component, then:
incoming.accept_step_result(
    record.round_id, RoundState.RED_PROPOSED,
    {"red_proposal": red_proposal},
    raw_output_ref="audit://red/raw-output",
)
```

`open_round` validates `round_request` and delegates creation to the manager.
`begin_attempt` delegates attempt accounting and retry limits. Before starting
the Judge attempt it reloads and validates the evidence bundle; incomplete
evidence closes the round as inconclusive before a Judge attempt is recorded.
For each successful component step, `accept_step_result` enforces the next legal state,
validates exact message contracts and task IDs, stores payloads, finishes the
attempt, then advances with storage references. It rejects unexpected artifact
names. Component payloads are not stored in the manager.

The state artifact requirements mirror `round_management.states`:

| State | Accepted artifacts |
|---|---|
| `RED_PROPOSED` | `red_proposal` |
| `TELEMETRY_COLLECTED` | none; pass its execution/audit reference as `raw_output_ref` |
| `EVIDENCE_VERIFIED` | `telemetry_evidence`; optional `reviewed_label_set`, `baseline_match_set` |
| `BLUE_PROPOSED` | `blue_proposal` |
| `CANDIDATE_EXECUTED` | `candidate_rule`, `candidate_match_set`; optional `baseline_match_set` |
| `JUDGED` | `judge_result`; stored judge evidence is reloaded and cross-checked first |

Artifact keys are the manager's names (`baseline_match_set`,
`candidate_match_set`) even though both payloads validate as `match_set`.

## Contract sources

Use shared schemas for `round_request`, `red_proposal`, `reviewed_label_set`,
`match_set`, `blue_proposal`, `candidate_rule`, `judge_result`,
`feedback_record`, and `error_response`. The full `telemetry_evidence` envelope
still has a local temporary schema. The Judge result is validated directly
against the shared contract; see [`../contracts/`](../contracts/README.md) for
the remaining temporary schemas.

## Cross-contract validation before a Judge result

The adapter requires stored references for the Blue proposal, compiled
candidate rule, baseline and candidate match sets, and reviewed labels before
it accepts `judge_result`. It reloads and validates those documents, then
checks that they match the frozen round's task, detection, rule version,
dataset, and proposal. It checks match roles, candidate references, compiled
SHA-256, completed execution, duplicate IDs, label review, and coverage. It
validates the Judge response against the shared Judge-result schema and checks
the evaluated result's criteria version against the frozen round criteria.
It does not yet compare every Judge-result provenance field with the stored
artifacts. An INCONCLUSIVE result with null task identity must be handled as
audit/error output; it cannot be linked to that round's feedback record.

Contradictory artifacts fail validation and fail the round. Missing or
incomplete evidence discovered before the Judge attempt takes the manager's
inconclusive path. The Judge decision is an object with a `status` field;
orchestration records that decision and does not calculate pass/reject.

## Errors

Submit component failures with `accept_error_response`. It validates and stores
the shared `error_response`, records the failed attempt, and applies the
contract's retryable/category information through the manager. It raises
`ComponentFailure` carrying the category, retry status, artifact reference, and
latest round record so the caller can decide whether to retry. Invalid output
is recorded as a nonretryable validation failure.
