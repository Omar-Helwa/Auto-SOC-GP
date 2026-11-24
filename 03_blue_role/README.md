# Blue role (`03_blue_role`)

Blue is the defender in AutoSOC. Given a detection rule (Sigma), the benign events it wrongly
alerts on (**false positives**) and the attack events it must keep catching (**must-detect**),
Blue proposes a **small edit** to the rule: an exclusion, or a narrower selection.

Blue only proposes. It never runs an attack, never judges its own work, and cannot change the
judge's criteria. The platform compiles and runs the edit, and the deterministic judge decides.

This folder is a standalone Python package, `autosoc_blue`. It imports nothing from other AutoSOC
folders, so it works inside the project (through an adapter) and outside it (Python, CLI, HTTP).

## How it works

```
blue_input --> validate --> context --> Proposer --> normalise --> PRE-FLIGHT --> blue_proposal
                                          ^                          |
                                          |   rejected: retry once   |
                                          +-- with the reasons ------+
                                          after the retry: deterministic fallback
```

Pre-flight applies the edits to the Sigma rule and checks them with a small local matcher:

- every false positive is no longer matched;
- every must-detect event is still matched;
- no exclusion relies only on attacker-controllable fields (for example `CommandLine`);
- the edit count is within `max_edits`; only allowed operations and fields; no wildcards.

If nothing passes, Blue returns an `error_response` (`missing_information`): the evidence does not
separate the false positives from the attacks. The judge stays the authority; pre-flight only avoids
wasting a Splunk run on an edit that is obviously wrong.

## Architecture (hexagonal)

```
autosoc_blue/
  core/        BlueEngine, context, normalise, pre-flight. Depends only on ports.py.
  ports.py     ModelGateway, EvidenceSource, RuleValidator, Proposer (interfaces)
  adapters/
    deterministic.py   baseline proposer, no AI, always the same answer
    llm.py             LLM proposer: versioned prompt, JSON-only answer, pre-flight feedback on retry
    validators.py      RuleValidator backed by the local Sigma matcher
    evidence.py        EvidenceSource: none / in-memory
    gateways/          mock (tests, demo), anthropic, openai; chosen by environment
  prompts/     blue_system.v0_1_0.md, blue_task.v0_1_0.md (package data, versioned)
  contracts/   JSON Schemas shipped with the package (copies of the shared contracts)
  schemas/     typed models + validation;  rule_edits/  apply edits + local Sigma matcher
  role.py      BlueRole.run(blue_input) -> dict   (what the orchestrator calls)
  cli.py, api.py, factory.py
```

`schemas/` and `rule_edits/` at the top of this folder are thin aliases of the package modules, so old
imports keep working.

**Deterministic proposer.** Builds an `add_exclusion` from the false positive's own `observed_fields`
(`equals` conditions) on allowed fields that the attacker does not control. It picks the smallest
set of conditions that makes every must-detect event fail at least one condition, then adds one more
safe condition to keep the exclusion narrow (for example `User` AND `ParentImage`). Attacker-controllable
fields are used only as extra conditions, never alone. If exclusions cannot work it tries
`narrow_selection` with values that all attack events share. Several false positives that use the same
fields are merged into one edit when that stays safe.

**LLM proposer.** Sends the system and task prompts to a `ModelGateway`, expects one JSON object, and
treats everything in the events as data. The answer goes through the same pre-flight as everything else.

## Install

```bash
pip install -e 03_blue_role                    # core: jsonschema + PyYAML
pip install -e "03_blue_role[http]"            # + FastAPI / uvicorn
pip install -e "03_blue_role[anthropic]"       # + anthropic SDK   (or [openai])
pip install -e "03_blue_role[dev]"             # + pytest, httpx, FastAPI
```

Python 3.11 or newer (the team uses 3.12).

## Run

**Python API**

```python
from autosoc_blue import BlueRole, build_engine

role = BlueRole()                       # deterministic proposer, no AI
proposal = role.run(blue_input)         # blue_proposal, or an error_response dict

engine = build_engine("mock")           # or "anthropic" / "openai"
result = engine.propose_with_trace(blue_input)
result.proposal, result.trace()         # trace = every attempt and why it was rejected
```

**CLI**

```bash
python -m autosoc_blue propose --input 03_blue_role/dev/fixtures/inputs/single_fp.json
python -m autosoc_blue propose --input blue_input.json --provider mock --out proposal.json --trace
python -m autosoc_blue validate --input proposal.json          # blue_input or blue_proposal
```

Exit codes: 0 ok, 1 no proposal (an `error_response` is printed), 2 configuration error.

**HTTP**

```bash
python -m autosoc_blue serve --port 8080       # needs the [http] extra
curl -X POST localhost:8080/propose -H 'content-type: application/json' \
     --data-binary @03_blue_role/dev/fixtures/inputs/single_fp.json
curl localhost:8080/health
```

`POST /propose` returns the proposal (200) or an `error_response` (422). `?trace=true` adds the attempts.

**Docker**

```bash
docker build -t autosoc-blue 03_blue_role
docker run -p 8080:8080 autosoc-blue
```

## Use a real model

Keys come from environment variables only. Nothing is stored in files.

| Variable | Meaning |
|---|---|
| `BLUE_MODEL_PROVIDER` | `none` (default, deterministic only), `mock`, `anthropic`, `openai` |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | key for the chosen provider |
| `BLUE_MODEL_ID` | model id. Default `claude-sonnet-5-5` (Anthropic) or `gpt-4.1` (OpenAI) |
| `BLUE_MODEL_TIMEOUT` | seconds, default 60 |
| `BLUE_ALLOW_PARTIAL` | `1` accepts a proposal that removes only some false positives |
| `BLUE_MOCK_MODE` | for the mock: `normal`, `bad_then_good`, `always_bad`, `malformed`, `timeout`, ... |

```bash
export BLUE_MODEL_PROVIDER=anthropic ANTHROPIC_API_KEY=...
python -m autosoc_blue propose --input blue_input.json --trace
```

If the model is down, times out, answers badly twice, or its edit fails pre-flight twice, Blue falls
back to the deterministic proposer. A missing key is a clear configuration error (exit 2), not a silent fallback.

## How it plugs into AutoSOC

- The orchestrator calls `BlueRole().run(blue_input)`. Same signature as its `MockBlueRole`;
  `task_id`, `prompt_version` and `detection_under_test` are copied from the input.
- `99_integration/adapters/blue_service.py` wraps Blue as a controller Service (same shape as
  `red_service.py`) and builds a full `blue_input` for the round, because the controller's default blue
  step only passes `task_id`.
- Edits use the operations and condition shapes of the `blue_proposal` contract, so the platform's rule
  compiler can turn them into a candidate rule.
- Demo of a full round with the real Red and the real Blue, stored in MongoDB:

```bash
docker run -d --name autosoc-mongo -p 27017:27017 mongo:7
python 99_integration/assembled_runs/run_with_real_red_and_blue.py [--provider mock]
```

## Tests

```bash
cd 03_blue_role && python -m pytest          # pre-existing contract tests + the new ones
```

Fixtures: `dev/fixtures/inputs/` (single false positive, two false positives, narrow only,
needs an attacker-controllable field, inseparable evidence).

## Not done / limits

- No retrieval or RAG; reference rules are not used (`reference_rules` is left out).
- The local matcher supports a subset of Sigma (see `rule_edits/sigma_match.py`); anything else is
  reported as "unverifiable", never as a pass.
- The deterministic proposer builds exact `equals` conditions: safe, but it only removes the false
  positives it has seen. Generalising is the job of a model, and of the judge's measurements.
- `autosoc_blue/contracts/` holds copies of the shared schemas; a test fails if they drift from the originals.
