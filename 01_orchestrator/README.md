# Orchestrator

The Orchestrator opens and manages one detection-improvement round. It freezes
the accepted `round_request`, coordinates the Red, Platform, Blue, and Judge
steps through `RoundWorkflow`, validates each contract boundary, stores
artifacts by reference, and closes the round as completed, failed, or
inconclusive. It does not calculate the Judge's decision.

The Python workflow is implemented, and a mock-only full-round runner is
available. Production use still needs real services to be supplied through the
`WorkflowServices` interface; this folder does not contain a production
composition for the component clients.

## Requirements and commands

- Python 3.10 or newer
- Install dependencies with `python -m pip install -r requirements.txt`.
- Run commands from this `01_orchestrator` directory.

Run the complete Orchestrator test suite:

```powershell
python -m unittest discover -s dev/tests -v
```

The suite exercises in-memory and Mongo persistence, contract checks, mock
round outcomes, and a fresh-workflow reload. Mongo integration tests are
skipped when no MongoDB server is reachable. The successful end-to-end round
uses mocks; it does not prove compatibility with the real Blue or Judge
interfaces.

Run a mock round in memory:

```powershell
python -m dev.sandbox.run_mock_round --scenario pass
```

See [`dev/sandbox/README.md`](dev/sandbox/README.md) for all scenarios and Mongo
options.

## Package layout

- [`round_management/`](round_management/): frozen request model, round state
  machine, attempt/retry policy, and in-memory, JSON-file, and Mongo stores.
- [`interfaces/`](interfaces/): input/output builders, contract validation,
  artifact storage adapters, and cross-contract evidence checks.
- [`workflow/`](workflow/): service protocols, workflow runner, and production
  Mongo composition helper.
- [`audit_records/`](audit_records/): immutable event model and Mongo/in-memory
  audit stores.
- [`feedback_store/`](feedback_store/): query facade for shared feedback
  records and the artifacts they reference; it does not duplicate records.
- [`dev/`](dev/): fixed fixtures, mock services, tests, and sandbox runner.

## Round lifecycle

```text
CREATED -> RED_PROPOSED -> TELEMETRY_COLLECTED -> EVIDENCE_VERIFIED
        -> BLUE_PROPOSED -> CANDIDATE_EXECUTED -> JUDGED
        -> COMPLETED (PASS or REJECT)
```

Any nonterminal state can instead end as `FAILED` or `INCONCLUSIVE`. The
Orchestrator requires each forward step in order. `INCONCLUSIVE` from the
Judge is a valid Judge outcome; missing required evidence can also cause the
Orchestrator to close a round as inconclusive before calling the Judge.

`task_id` is also the round ID. The frozen request contains detection, benign
constraints, dataset identity, Judge criteria, pinned versions, optional
permitted evidence references, and attempt/step-time limits. The schemas in
`00_shared_contracts/` define the canonical message shapes where published.

## Workflow and storage

`create_mongo_workflow(repository, services)` initializes repository
collections and round indexes, then wires Mongo-backed round, contract
artifact, and audit stores to that repository. Use this factory for durable
production persistence. `create_workflow(...,
allow_non_mongo_stores=True)` is intended for tests and development.

The `services` argument must provide `red.run`, `blue.run`, `judge.run`, and
the Platform methods listed in [`workflow/services.py`](workflow/services.py).
The workflow stores the accepted `round_request`, component contract outputs,
feedback record, audit events, and references to those records. `RoundManager`
is authoritative for the round's state and transition history.

The workflow retries classified retryable failures up to the frozen per-step
limit. Step timeouts are detected by the round manager, but a timed-out
synchronous service call is not forcibly cancelled. See the production gaps
below before relying on the timeout as a hard execution bound.

## Current production gaps

- **Real service composition (item 4):** production Red, Blue, Judge, and
  Platform clients are not bound in this folder. An application composition
  must inject them and provide Platform's approved-search authorization.
- **Timeout enforcement (item 6):** the manager detects an expired step, but
  the workflow cannot stop a synchronous call that is still blocked.
- **Restart recovery (item 7):** a process crash can leave an attempt marked
  `running`; there is no stale-attempt recovery policy yet.
- **Partial writes (item 8):** exact-payload retries reuse saved artifacts,
  but failed multi-document writes can leave unreferenced Mongo documents.
  No cleanup or transaction strategy is implemented.
- **Audit store selection (item 9):** `create_mongo_workflow()` selects Mongo
  audit storage. A caller that builds Mongo stores through the lower-level
  `create_workflow()` must explicitly supply a Mongo audit writer or audit
  events remain in memory.
- **Audit schema validation (item 10):** Mongo currently reports that no
  `audit_record` schema is published and stores those documents unvalidated.
  The shared contract and repository need that schema registered before Mongo
  can validate Orchestrator audit records.
- **Real-component integration tests (item 11):** full-round tests use mock
  services. Blue's Sigma handoff and the Judge's real input/output round trip
  are not covered by an integration test.
- **Judge input contract:** the shared project defines `judge_result`, but no
  shared Judge-input contract. The temporary Orchestrator bundle currently
  differs from the input shape required by the deterministic Judge. Agree on
  and implement that handoff before connecting the real Judge.
- **Blue input:** the round request contains Splunk SPL, while Blue requires
  Sigma. Supply a trusted, matching Sigma representation; the Orchestrator
  does not convert or relabel SPL. The edit-constraint policy is also not
  versioned in the frozen round request.

The detailed interface limitations are in
[`workflow/README.md`](workflow/README.md) and
[`interfaces/outputs/README.md`](interfaces/outputs/README.md).

## Integrity and feedback

`RoundManager.verify_integrity(round_id)` checks the persisted request
fingerprint, state history, timestamps, attempts, artifacts, and terminal
outcome. It detects inconsistent records; it is not a protection against
deliberate database edits.

After a Judge result is accepted, the workflow persists a shared
`feedback_record` before closing the round. `workflow.outputs.feedback_store`
can retrieve that record and resolve its linked artifacts. Its
`retrieval_eligible` hint is true only for a `PASS`; automatic feedback-memory
selection and prompt updates are not implemented.
