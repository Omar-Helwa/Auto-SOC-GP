# Orchestrator

The Orchestrator opens and manages one detection-improvement round. It freezes
the accepted `round_request`, sequences Red, Platform, Blue, and Judge in the
required order, validates contract boundaries, records attempts and audit
events, stores artifacts by reference, and closes the round. It does not author
role proposals or calculate the Judge's decision.

`shared_services.controller.RoundController` is the Mongo-backed application
entry point and delegates to this workflow. The Orchestrator workflow is the
only implementation of round ordering, retry policy, audit, and feedback.
Production clients are composed in `99_integration/`.

## Requirements and commands

- Python 3.10 or newer
- Install dependencies with `python -m pip install -r requirements.txt`.
- Run commands from this `01_orchestrator` directory.

Run the complete Orchestrator test suite:

```powershell
python -m unittest discover -s dev/tests -v
```

The suite covers in-memory and Mongo persistence, contract checks, mock round
outcomes, and workflow reload. Mongo integration tests are skipped when no
MongoDB server is reachable.

Run a mock round in memory:

```powershell
python -m dev.sandbox.run_mock_round --scenario pass
```

See [`dev/sandbox/README.md`](dev/sandbox/README.md) for scenarios and Mongo
options.

## Package layout

- [`round_management/`](round_management/): frozen request model, state
  machine, attempt/retry policy, and in-memory, JSON-file, and Mongo stores.
- [`interfaces/`](interfaces/): boundary documentation and the one local
  telemetry-envelope schema.
- [`orchestrator_interfaces/`](orchestrator_interfaces/): public input/output
  builders, contract validation, artifact storage, and cross-contract checks.
- [`workflow/`](workflow/): service protocols, state-driven runner, and Mongo
  composition helper.
- [`audit_records/`](audit_records/): immutable event model and Mongo/in-memory
  audit stores.
- [`feedback_store/`](feedback_store/): query facade for shared feedback
  records and referenced artifacts.
- [`dev/`](dev/): fixtures, mock services, tests, and sandbox runner.

## Round lifecycle

```text
CREATED -> RED_PROPOSED -> TELEMETRY_COLLECTED -> EVIDENCE_VERIFIED
        -> BLUE_PROPOSED -> CANDIDATE_EXECUTED -> JUDGED
        -> COMPLETED (PASS or REJECT)
```

Any nonterminal state may instead end as `FAILED` or `INCONCLUSIVE`.
`INCONCLUSIVE` from the Judge is a valid result; missing required evidence can
also close the round as inconclusive before the Judge is called.

`task_id` is also the round ID. The frozen request contains detection, benign
constraints, dataset identity, Judge criteria, pinned versions, optional
permitted evidence references, and attempt/step-time limits.
`00_shared_contracts/` defines canonical message shapes.

## Workflow and storage

`create_mongo_workflow(repository, services)` initializes repository
collections and round indexes, then shares the repository across Mongo-backed
round, contract-artifact, and audit stores. Use it for durable production
persistence. `create_workflow(..., allow_non_mongo_stores=True)` is intended
for tests and development.

The injected services provide `red.run`, `blue.run`, `judge.run`, and the
Platform methods listed in [`workflow/services.py`](workflow/services.py).
Accepted `round_request`, component outputs, feedback, and audit events are
persisted. `RoundManager` is authoritative for state and transition history.
Retryable failures are retried up to the frozen per-step limit.

## Remaining production gaps

- Platform production composition must provide approved-operation
  authorization and real Splunk execution.
- Synchronous service calls are not forcibly cancelled when their timeout
  expires.
- A process crash can leave an attempt marked `running`; stale-attempt recovery
  is not implemented.
- Failed multi-document writes can leave unreferenced Mongo documents; no
  transaction or cleanup strategy is implemented.
- Mongo currently stores Orchestrator `audit_record` documents without
  repository-level schema validation because no shared audit schema is
  published.
- The assembled runner uses the real Platform adapter
  (`99_integration/adapters/platform_service.py`). Its tests use a local
  Splunk stub; a live round needs a human-reviewed evaluation set.
- Blue accepts `sigma` and `spl`. The Platform's trusted rule-view adapter
  must provide an explicit format and a detection identity/version matching
  the frozen request; there is no implicit conversion or relabeling.

See [`workflow/README.md`](workflow/README.md) and
[`interfaces/outputs/README.md`](interfaces/outputs/README.md) for boundary
details.

## Integrity and feedback

`RoundManager.verify_integrity(round_id)` checks the persisted request
fingerprint, state history, timestamps, attempts, artifacts, and terminal
outcome. It detects inconsistent records; it is not protection against
deliberate database edits.

After a Judge result is accepted, the workflow persists a shared
`feedback_record` before closing the round. `workflow.outputs.feedback_store`
can retrieve the record and resolve linked artifacts. Its
`retrieval_eligible` hint is true only for `PASS`; automatic feedback-memory
selection and prompt updates are not implemented.
