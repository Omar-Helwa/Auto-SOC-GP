# 02_red_role — Red role component

The Red role proposes **one bounded, benign workflow** that could trip a
detection rule as a false positive. It PROPOSES only: it never executes, labels
telemetry, edits rules, or judges success. Output is always a contract-valid
`red_proposal` or an `error_response`.

## Status: complete (Epics A–G)

| Epic | What | Where |
|------|------|-------|
| A | Contracts (`red_proposal`, `red_input`, error/evidence) | `00_shared_contracts/`, `interfaces/inputs/` |
| B | Typed models + schema validation | `schemas/` |
| C | Scenario families + per-round bounds & safety | `scenarios/` |
| D | Red-only context builder (isolation) | `role_context/` |
| E | Versioned prompts (system + task) | `prompts/` |
| F | Model-gateway interface + parser + mock | `interfaces/`, `dev/mocks/` |
| G | Public `RedRole` entry, fixtures, tests, sandbox | `interfaces/red_role.py`, `dev/` |

## The flow

```
red_input dict
  -> validate + parse           (interfaces/inputs/input_adapter.py)
  -> build red-only context     (role_context/builder.py)
  -> render versioned prompt    (prompts/registry.py)
  -> call model gateway         (interfaces/model_gateway.py  <- mock or real)
  -> parse response -> proposal (interfaces/parser.py)
  -> enforce round bounds+safety(scenarios/bounds.py)
  -> validate + serialize       (schemas/serializer.py)
  = red_proposal   (or error_response on any failure)
```

Error mapping: missing input field -> `missing_information`; malformed input or
model output / out-of-scope proposal -> `validation`; gateway timeout ->
`timeout`; gateway down -> `dependency`; internal invariant break -> `internal`.

## Run it (no live model needed)

```bash
cd 02_red_role
python -m pip install -r requirements.txt

python dev/sandbox/run.py                      # normal round -> red_proposal
python dev/sandbox/run.py --mode timeout       # -> error_response (timeout)
python dev/sandbox/run.py --mode out_of_scope  # -> error_response (validation)
python -m pytest                               # 26 tests
```

## Using it from code / integration

```python
from interfaces.red_role import RedRole
from mock_gateway import MockModelGateway        # dev mock; swap for real gateway

red = RedRole(MockModelGateway(mode="normal"))
result = red.run(red_input_dict)                 # -> red_proposal or error_response dict
```

The controller in `shared_services/` calls Red through
`99_integration/adapters/red_service.py`, which wraps `RedRole` as a Service.
To go live, inject Member 5's hosted-model gateway instead of the mock — nothing
else changes.

## Boundaries (by design)

- No execution, labeling, rule edits, or verdicts — structurally impossible
  (no result fields; `constraints_ack` is pinned true).
- Context is a pure function of the input (isolation): no other round, role, or
  evidence beyond the input's `permitted_evidence_refs` can enter.
- The model only supplies the scenario; the component stamps `task_id`,
  `prompt_version`, `detection_under_test`, `proposal_id`, and `contract_version`.
