# `shared_services/` — datastore + controller (team infrastructure)

MongoDB persistence for every shared contract, plus a controller that relays a
round's data between the services in Architecture 1 order. Depends on **no**
member's component (01–05) — only on the contract schemas in
`00_shared_contracts/`. Owned by the team; coordinate changes with the
Orchestrator (M1) and Platform (M5) owners.

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

One collection per contract (see `config.CONTRACT_COLLECTIONS`):

| Contract | Collection | Validated on write? |
|----------|-----------|---------------------|
| round_request | `round_requests` | pending (no schema yet) |
| red_proposal | `red_proposals` | ✅ yes |
| telemetry_evidence | `telemetry_evidence` | pending (M5) |
| blue_proposal | `blue_proposals` | pending (M3) |
| candidate_rule | `candidate_rules` | pending (M5) |
| judge_result | `judge_results` | pending (M4) |
| feedback_record | `feedback_records` | pending (M1) |
| error_response | `error_responses` | ✅ yes |
| red_input (aux) | `red_inputs` | ✅ yes |

Validation is **app-layer**: a document is checked against its contract's schema
before insert (`ContractViolation` is raised on failure). Contracts without a
published schema are stored unvalidated with a warning, and begin validating
automatically once their owner drops a `*.schema.json` into the contract folder —
no code change needed.

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
