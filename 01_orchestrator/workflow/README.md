# Orchestrator workflow

`RoundWorkflow` coordinates an Architecture 1 round. It uses the public
interface adapters for validation and persistence and leaves round state,
attempt limits, and terminal outcomes to `RoundManager`.

## Composition

The application injects implementations of the protocols in `services.py`:
`red.run`, `blue.run`, `judge.run`, and the four Platform methods. This folder
contains the protocols and mock implementations under `dev/mocks`; it does
not contain production clients or a production service composition.

For durable production storage, use `create_mongo_workflow(repository,
services)`. It initializes repository collections and round indexes, then
shares the repository across round, contract-artifact, and audit storage. Use
`create_workflow(..., allow_non_mongo_stores=True)` for tests and development.
If the lower-level factory receives Mongo stores, also pass a Mongo audit
writer; without one, audit storage defaults to memory. Prefer
`create_mongo_workflow` for production.

```python
from workflow import create_mongo_workflow

workflow = create_mongo_workflow(repository, services)
result = workflow.run_round(round_request)
```

Red, Blue, and Judge return their contract payloads. They may return a mapping
directly or a `WorkflowStepOutput` containing `messages`, the original
`raw_output`, and `model_id`. The Platform returns a `WorkflowStepOutput` for
telemetry collection, evidence verification, and candidate execution. See
`services.py` and `models.py` for the method and value shapes.

## Running and resuming rounds

`run_round(round_request)` validates and opens the round, then runs each step
in order. `run_open_round(round_id)` continues a saved nonterminal round when
there is no active attempt. Retryable failures are persisted through the
`error_response` contract and retried within the frozen attempt limit. A
nonretryable failure closes the round. A process crash can leave an attempt
marked `running`; stale-attempt recovery is not implemented yet.

Step timeouts are checked when results or transitions are accepted. Service
calls are synchronous and are not cancelled when the timeout expires, so this
is not a hard limit on how long a blocked call can occupy the workflow.

## Audit and artifacts

The workflow records `round_opened`, component start/completion/failure, and
`round_closed` events. Events link to input/output artifact references,
attempts, state transitions, validation results, execution references,
component output, errors, and Judge decisions. Contract payloads remain in
the contract artifact store. Exact-payload retries reuse existing artifact
references; the round record only treats artifacts attached to its transition
history as accepted. A failed multi-artifact write can still leave unreferenced
documents; cleanup or transaction handling is not implemented.

Mongo audit writes use the shared repository's `audit_record` mapping. The
repository currently warns that no audit-record schema is published and
stores these documents without repository-level schema validation. The
Orchestrator checks strict JSON values and required event identifiers.

## Integration gaps

The temporary Orchestrator Judge input contains the shared match sets, reviewed
labels, and frozen criteria. The deterministic Judge currently expects a
different shape: `evaluation_set`, `baseline`, `candidate`, `reviewed_labels`,
and `provenance`, plus a complete event inventory and other Judge-specific
fields. The shared contracts define `judge_result`, but do not define this
input. A real Judge call requires an agreed input contract and mapping; the
mock Judge does not test that integration.

Blue requires Sigma, while `round_request.detection` supplies Splunk SPL. The
workflow requires a trusted, identity- and version-matched Sigma
representation; it does not convert or relabel SPL. Blue edit constraints are
supplied by the caller and are not frozen or versioned in the request.

The Platform service must be implemented by the application composition and
provide approved-search authorization. The current end-to-end and Mongo
reload tests use mocks; they do not verify real Blue or Judge compatibility.
See [`../interfaces/outputs/README.md`](../interfaces/outputs/README.md) for
input details.
