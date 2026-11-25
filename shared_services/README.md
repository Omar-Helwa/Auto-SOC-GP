# `shared_services/` - datastore + controller (team infrastructure)

MongoDB persistence for shared contract messages and auxiliary round/audit
records, plus a controller that relays round data in Architecture 1 order.
Validation uses shared schemas, with an explicit temporary Orchestrator telemetry
schema fallback until the canonical shared contract is published.
Owned by the team; coordinate changes with the Orchestrator (M1) and Platform (M5).

## Layout

```
shared_services/
  config.py                 # Mongo URI + DB name (env-overridable) + collection map
  datastore/
    schema_registry.py      # maps each contract -> its JSON Schema file
    validation.py           # app-layer validation against those schemas
    repository.py           # MongoRepository: one collection per contract
  controller/
    services.py             # Service interface + registry + mock helpers
    round_controller.py     # runs a round, persisting every message
  scripts/
    init_db.py              # create collections + indexes (idempotent)
    demo_round.py           # run one mock round end-to-end
  tests/                    # pytest suite (skips if Mongo is down)
```

## The "DB schema"

One collection per stored contract message (see `config.CONTRACT_COLLECTIONS`):

| Contract | Collection | Validated on write? |
|----------|-----------|---------------------|
| round_request | `round_requests` | ✅ yes |
| red_proposal | `red_proposals` | ✅ yes |
| telemetry_evidence | `telemetry_evidence` | temporary Orchestrator envelope schema until the shared schema is published |
| reviewed_label_set | `reviewed_label_sets` | yes |
| blue_proposal | `blue_proposals` | ✅ yes |
| candidate_rule | `candidate_rules` | ✅ yes (draft) |
| match_set | `match_sets` | yes |
| judge_result | `judge_results` | yes |
| feedback_record | `feedback_records` | yes |
| error_response | `error_responses` | ✅ yes |
| red_input (aux) | `red_inputs` | ✅ yes |
| audit_record (aux) | `audit_records` | no: Orchestrator audit document |
| round_record (aux) | `rounds` | no: orchestrator state, written by `MongoRoundStore` |

Validation is **app-layer**: a document is checked against its contract's schema
before insert (`ContractViolation` is raised on failure). Contracts without a
published schema are stored unvalidated with a warning. The init script reports
temporary schema fallbacks separately; those must be replaced when the canonical
shared schema is published.
The temporary telemetry fallback reads the existing Orchestrator interface schema
and is replaced after restart when the canonical shared schema is added.

## Setup & run

```bash
pip install -r shared_services/requirements.txt

# Provision the database structure (uses mongodb://localhost:27017, db "autosoc")
python -m shared_services.scripts.init_db

# Run one mock round into MongoDB
python -m shared_services.scripts.demo_round

# Tests (throwaway autosoc_test DB; skipped if Mongo is down)
python -m pytest shared_services/tests
```

Override the connection with `AUTOSOC_MONGO_URI` and `AUTOSOC_DB`.

## Wiring real services

The controller relays to anything implementing `Service.handle(payload) ->
ServiceResult`. Replace a mock with a real component by registering it under the
same role — the controller is unchanged:

```python
registry.register("red", MyRealRedService())      # instead of static_service(...)
```
