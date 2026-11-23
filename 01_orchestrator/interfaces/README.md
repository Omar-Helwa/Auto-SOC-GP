# Orchestrator interfaces

The interface adapters connect contract messages and artifact storage to
`RoundManager`. They validate inputs and outputs, persist contract documents,
and attach stored references to the corresponding round transition. The
adapters do not call components themselves; `workflow.RoundWorkflow` invokes
the injected services and routes their outputs through these adapters.

## Modules

- [`validation.py`](validation.py): schema discovery and strict JSON contract
  validation. Published shared/component schemas take precedence over the
  local temporary schemas.
- [`artifacts.py`](artifacts.py): contract-artifact storage protocol,
  in-memory implementation, Mongo repository adapter, and retry-safe
  `save_once` helper.
- [`inputs/adapter.py`](inputs/adapter.py): opens a round, begins attempts,
  validates and persists returned artifacts or `error_response` messages, and
  advances or closes the round.
- [`outputs/adapter.py`](outputs/adapter.py): builds Red, Blue, and Judge
  inputs; checks evidence before judging; and saves feedback before closing a
  judged round.
- [`outputs/cross_contract.py`](outputs/cross_contract.py): checks that the
  stored proposals, candidate rule, match sets, labels, and frozen round refer
  to compatible tasks, detections, versions, datasets, and executions.

## Storage and lifecycle

The round record stores references, not copies of component contract
messages. Both adapters must share the same `RoundManager` and artifact store.
Use `create_mongo_workflow()` for Mongo-backed rounds, artifacts, and audit;
the separate adapters are also available for tests and controlled integration.

An artifact written before a later write or round transition fails can remain
in storage without a round reference. `save_once` reuses identical task
artifacts on retry, but there is no cleanup job or transaction covering
multiple artifact writes and a round update.

## Contract status and known gaps

Published contracts are used for `round_request`, `red_input`, proposals,
reviewed labels, match sets, candidate rules, `judge_result`,
`feedback_record`, and `error_response`. Two local schemas remain temporary:
the full `telemetry_evidence` envelope and the outer `judge_input` handoff.
Their status is in [`contracts/README.md`](contracts/README.md).

The Judge result is schema-validated and its task ID is checked when present.
For PASS/REJECT, the Orchestrator also checks the criteria version. It does
not yet compare every result provenance field against the stored source
artifacts. An INCONCLUSIVE Judge result with a null task ID is valid for an
unreadable input in the Judge-result schema, but must not be associated with a
round feedback record; that semantic case still needs explicit handling.

Blue's published input requires Sigma, but the frozen request carries Splunk
SPL. The builder fails closed unless the caller supplies an approved,
identity/version-matched Sigma representation. Edit constraints are caller
supplied and do not currently have a frozen policy version in `round_request`.
The Orchestrator does not convert SPL or create a policy on its own.

Install [`requirements.txt`](../requirements.txt) for schema validation and
Mongo support. Run the Orchestrator suite from `01_orchestrator` with
`python -m unittest discover -s dev/tests -v`.
