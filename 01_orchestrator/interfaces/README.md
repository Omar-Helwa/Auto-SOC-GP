# Orchestrator interfaces

This folder contains boundary documentation and the one Orchestrator-local
telemetry schema. The Python adapters that validate inputs and outputs, persist
contract documents, and attach references to `RoundManager` live in
[`../orchestrator_interfaces/`](../orchestrator_interfaces/).

## Modules

- [`../orchestrator_interfaces/validation.py`](../orchestrator_interfaces/validation.py):
  strict JSON validation using shared and
  component schemas.
- [`../orchestrator_interfaces/artifacts.py`](../orchestrator_interfaces/artifacts.py):
  artifact-store protocol, in-memory and Mongo
  implementations, and retry-safe `save_once`.
- [`../orchestrator_interfaces/inputs/adapter.py`](../orchestrator_interfaces/inputs/adapter.py):
  opens rounds, manages attempts,
  validates/persists artifacts and errors, and advances state.
- [`../orchestrator_interfaces/outputs/adapter.py`](../orchestrator_interfaces/outputs/adapter.py):
  builds Red, Blue, and Judge
  inputs; validates evidence before judging; and saves feedback.
- [`../orchestrator_interfaces/outputs/cross_contract.py`](../orchestrator_interfaces/outputs/cross_contract.py):
  checks that
  proposals, rules, match sets, labels, and frozen requests agree on task,
  detection, versions, datasets, and executions.

## Storage and lifecycle

Round records store references rather than copies of component messages. Both
adapters must share the same `RoundManager` and artifact store.
`create_mongo_workflow()` wires Mongo-backed round, artifact, and audit stores.
Artifacts written before a later write or state transition fails may remain
unreferenced; retries reuse identical artifacts, but multi-document writes are
not transactional.

## Contract status

Published shared/component schemas are authoritative for requests, proposals,
Blue/Judge inputs and outputs, labels, match sets, candidate rules, feedback,
and errors. The full `telemetry_evidence` envelope still uses an Orchestrator
local schema because the shared telemetry folder currently publishes the
evidence-reference and reviewed-label contracts only.

Blue input accepts explicit `sigma` and `spl` formats. The Platform's trusted
rule-view adapter supplies the rule text and must preserve the frozen
detection ID and rule version. The Orchestrator does not convert or relabel
rule text. Edit constraints are supplied by the Platform service.

The Judge input uses the shared `judge_input` schema. The Judge result is
validated against the shared `judge_result` schema and cross-checked against
the stored evidence. Provenance matching can be expanded further; see
[`outputs/README.md`](outputs/README.md).

Use the `orchestrator_interfaces` Python package in code. The physical
`interfaces/` folder is retained for schemas and documentation; it is not an
import package, so it cannot shadow Red's `interfaces` package.

Install [`requirements.txt`](../requirements.txt) for schema validation and
Mongo support. Run tests from `01_orchestrator` with
`python -m unittest discover -s dev/tests -v`.
