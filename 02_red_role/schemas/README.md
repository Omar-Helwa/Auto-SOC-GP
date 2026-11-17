# `02_red_role/schemas/` — local models & validation (Epic B)

The Red component's local representation of the contracts, plus the validator
and serializer. The JSON Schema files in `00_shared_contracts/` (and
`interfaces/inputs/red_input.schema.json`) remain the single source of truth —
this code loads and validates against them, it does not re-encode the rules.

## Modules

| Module | Purpose |
|--------|---------|
| `constants.py` | Closed vocabularies (families, actions, evidence/error types) + bounds. Kept in sync with the schema by a drift test. |
| `_loader.py` | Finds and caches the JSON Schema files relative to the repo root. |
| `validation.py` | **B3** — `validate_red_proposal / validate_red_input / ...` → `ValidationResult`. |
| `models.py` | **B1/B2** — `RedProposal` and `RedInput` dataclasses with `from_dict` / `to_dict`. |
| `errors.py` | **B4** — `build_error_response(...)` for contract-valid failures. |
| `serializer.py` | **B4** — `proposal_to_contract(...)` validates before emitting; raises `RedContractError` otherwise. |

## Usage

```python
from schemas import models, serializer, validation, errors

# Produce a validated proposal (raises RedContractError if it would be invalid)
payload = serializer.proposal_to_contract(my_red_proposal)

# Validate an incoming request; classify a failure for the error envelope
result = validation.validate_red_input(incoming)
if not result.ok:
    category = validation.input_error_category(result)   # missing_information | validation
    err = errors.build_error_response(category, result.summary(), task_id=incoming.get("task_id"))
```

## Running the tests

```
cd 02_red_role
python -m pip install -r requirements.txt
python -m pytest
```

Tests live in `dev/tests/`. `conftest.py` puts this component root on `sys.path`
(so `import schemas` works) and loads the shared contract example files as
fixtures. Run from the `02_red_role` directory to avoid name clashes with other
components' `schemas/` packages until final integration repackages them.
