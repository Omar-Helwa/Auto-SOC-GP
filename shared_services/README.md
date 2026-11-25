# `shared_services/` - shared persistence and controller facade

Cross-component MongoDB persistence for shared contracts, round state, audit
records, and feedback. `RoundController` is the Mongo-backed application entry
point and delegates the full lifecycle to `01_orchestrator/workflow`. This
package does not define a second step list, retry policy, or decision path.

## Layout

```text
shared_services/
  config.py                 # Mongo URI, database name, and collection map
  datastore/
    schema_registry.py      # contract -> shared JSON Schema
    validation.py           # app-layer schema validation
    repository.py           # MongoRepository
  controller/
    services.py             # component client boundary adapters
    round_controller.py     # public facade over the Orchestrator workflow
  scripts/
    init_db.py              # create collections and indexes
    demo_round.py           # mock round; Judge is INCONCLUSIVE
  tests/                    # facade, adapter, and datastore tests
```

## Persistence

Contract messages are stored in their contract collections. Validation is
app-layer: a message is checked against its shared schema before insertion.
Auxiliary round and audit records are written by the Orchestrator's Mongo
storage adapters. Audit records currently have no published shared schema.

| Contract | Collection |
|---|---|
| `round_request` | `round_requests` |
| `red_proposal` | `red_proposals` |
| `telemetry_evidence` | `telemetry_evidence` |
| `reviewed_label_set` | `reviewed_label_sets` |
| `blue_proposal` | `blue_proposals` |
| `candidate_rule` | `candidate_rules` |
| `match_set` | `match_sets` |
| `judge_result` | `judge_results` |
| `feedback_record` | `feedback_records` |
| `error_response` | `error_responses` |
| Orchestrator state | `rounds` |
| Orchestrator audit | `audit_records` |

## Setup and run

```powershell
python -m pip install -r shared_services/requirements.txt
python -m shared_services.scripts.init_db
python -m shared_services.scripts.demo_round
python -m pytest shared_services/tests
```

The repository-root `.env` supplies `MONGODB_URI`; `AUTOSOC_MONGO_URI`
overrides it, and `AUTOSOC_DB` selects the database. If the initial MongoDB
connection cannot be established, the repository logs a warning and falls
back to process-local `mongomock`. This data is temporary and is not
synchronized to Atlas. Authentication or malformed-URI errors are surfaced.
Set `fallback_to_mock=False` to require MongoDB.

Tests use a local endpoint by default so they never clean up data in the
application Atlas cluster. Set `AUTOSOC_TEST_MONGO_URI` only for an isolated
test cluster.

## Wiring component clients

`RoundController` accepts the Orchestrator's `WorkflowServices` shape
(`red.run`, `blue.run`, `judge.run`, and Platform operations). Existing
component adapters that return `ServiceResult` can be wrapped with
`WorkflowComponentAdapter`:

```python
services.red = WorkflowComponentAdapter(red_client, "red_proposal")
controller = RoundController(repository, services)
result = controller.run_round(round_request)
```

Application composition belongs in `99_integration/`; workflow ordering and
state policy remain in `01_orchestrator/`.
