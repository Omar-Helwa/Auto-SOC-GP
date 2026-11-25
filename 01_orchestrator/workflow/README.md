# Orchestrator workflow

`RoundWorkflow` runs one Architecture 1 round through the public interface
adapters. It owns sequencing and retry behavior while `RoundManager` owns
persisted state and terminal outcomes. `shared_services.controller.RoundController`
is the Mongo-backed application facade over this workflow.

## Composition

The application injects the protocols in `services.py`: `red.run`,
`blue.run`, `judge.run`, and the Platform operations. The workflow package
contains protocols and development mocks, not production component clients.
The application composition belongs in `99_integration/`.

For durable storage use `create_mongo_workflow(repository, services)`. It
shares a repository across round, contract-artifact, and audit stores. Use
`create_workflow(..., allow_non_mongo_stores=True)` for tests and development.
If the lower-level factory receives Mongo stores, also supply a Mongo audit
writer; otherwise audit storage defaults to memory.

Red, Blue, and Judge return contract payloads directly or a
`WorkflowStepOutput` with messages, raw response, and model metadata. Platform
returns a `WorkflowStepOutput` for telemetry collection, evidence
verification, and candidate execution.

## Running and resuming rounds

`run_round(round_request)` validates and opens a round, then runs each step in
order. `run_open_round(round_id)` continues a saved nonterminal round when
there is no active attempt. Retryable failures are persisted through the
`error_response` contract and retried within the frozen attempt limit. A
nonretryable failure closes the round. Stale-attempt recovery is not
implemented.

Step timeouts are checked when results or transitions are accepted. Synchronous
service calls are not cancelled when a timeout expires, so the timeout is not
a hard bound on blocked service calls.

## Audit and artifacts

The workflow records round-opened, component start/completion/failure, and
round-closed events. Events link to input/output artifact references, attempts,
state transitions, validation results, execution references, component output,
errors, and Judge decisions. Exact-payload retries reuse artifacts, while the
round record only treats artifacts attached to its transition history as
accepted. Failed multi-artifact writes can leave unreferenced documents.

Mongo audit writes use the shared repository's `audit_record` mapping. The
repository currently stores these documents without repository-level schema
validation because a shared audit schema is not published.

## Integration requirements

The workflow assembles the shared `judge_input` contract from the frozen
baseline/candidate match sets, reviewed labels, criteria, and pinned versions.
The deterministic Judge validates that bundle and returns the shared
`judge_result`.

Blue accepts the explicit `sigma` and `spl` formats. The Platform's trusted
rule-view adapter must supply a supported format and a detection
identity/version matching the frozen request. The Orchestrator does not
implicitly convert or relabel rule text.

The production Platform service must enforce approved-operation
authorization. The assembled smoke runner uses partial fixtures and the real
Judge, so it cannot produce an acceptance verdict or represent measured
Splunk execution.
