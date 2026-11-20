# Orchestrator

The orchestrator's current implementation is the **round management core** for AutoSOC Architecture 1. It creates rounds from validated requests, tracks the fixed workflow state, records attempts and artifact references when provided, and closes rounds as completed, failed, or inconclusive.

This package does not call the red role, platform, blue role, or judge. Callers provide component results and advance the round. The storage interface is intentionally separate so a database-backed store can be added later.

## Requirements

- Python 3.7 or newer
- No third-party Python packages

See [`requirements.txt`](requirements.txt).

## Package layout

- `round_management/models.py` — round configuration, transition, attempt, and record data models; validation and serialization.
- `round_management/states.py` — Architecture 1 states and allowed transitions.
- `round_management/errors.py` — round-management exceptions and accepted round error categories.
- `round_management/store.py` — storage interface, in-memory store, and JSON-file store.
- `round_management/manager.py` — lifecycle operations, attempts, retries, timeouts, terminal outcomes, and integrity checks.
- `round_management/__init__.py` — public package exports.
- `dev/tests/` — isolated unit tests.

## Round lifecycle

The normal state sequence is:

```text
CREATED
  -> RED_PROPOSED
  -> TELEMETRY_COLLECTED
  -> EVIDENCE_VERIFIED
  -> BLUE_PROPOSED
  -> CANDIDATE_EXECUTED
  -> JUDGED
  -> COMPLETED
```

Any nonterminal state can instead end as `FAILED` or `INCONCLUSIVE`. Skips and backward transitions are rejected.

## Basic use

Run commands from the `01_orchestrator` directory so `round_management` is importable.

```python
from round_management import InMemoryRoundStore, RoundManager, RoundState

request = {
    "task_id": "task-001",
    "detection": {"name": "suspicious_powershell", "spl": "index=win EventCode=4688"},
    "dataset_ref": "dataset://lab/v1",
    "criteria": {"min_fp_reduction": 0.2, "max_attack_loss": 0},
    "versions": {
        "prompt": "p1",
        "model": "m1",
        "rule": "r1",
        "dataset": "d1",
        "criteria": "c1",
        "contracts": "v1",
    },
}

manager = RoundManager(InMemoryRoundStore())
round_record = manager.create_round(request)
round_id = round_record.round_id

# An attempt targets the next state. Recording attempts is optional for callers.
manager.begin_attempt(round_id)
manager.finish_attempt(
    round_id,
    "succeeded",
    raw_output_ref="audit://round-001/red-output",
)
manager.advance(
    round_id,
    RoundState.RED_PROPOSED,
    artifact_name="red_proposal",
    artifact_ref="audit://round-001/red-output",
)
```

Repeat `advance()` for each state in order. Use `fail()` or `mark_inconclusive()` to close early. After advancing to `JUDGED`, close with the judge's decision and a feedback reference:

```python
manager.complete(round_id, "pass", "feedback://round-001")
manager.verify_integrity(round_id)
```

The manager records the supplied judge decision; it does not calculate or validate the judge's decision against a judge-result payload.

## Requests and configuration

Required request fields are `task_id`, `detection`, `dataset_ref`, `criteria`, and `versions`. `versions` must contain nonempty strings for `prompt`, `model`, `rule`, `dataset`, `criteria`, and `contracts`.

Optional fields:

- `max_attempts_per_step` — positive integer; defaults to `2`.
- `step_timeout_seconds` — positive integer; defaults to `300`.

Detection, criteria, versions, and error details must be strict JSON data. Config mappings and nested lists are frozen after validation. A config fingerprint is stored with each round.

## Attempts, retries, and timeouts

`begin_attempt()` records a running attempt for the next workflow state. `finish_attempt()` records it as `succeeded` or `failed`, with an optional raw-output reference. Failed attempts remain in the log; if the last configured attempt fails, the round closes as `FAILED`. After a successful attempt, the caller advances the round with `advance()`.

Timeouts apply per state, not per attempt. The timer starts when a round is created and resets on each state transition, so retries in the same state share the timeout. The manager checks timeouts when beginning or finishing an attempt and when accepting a state transition. `enforce_timeout()` can also be called by a polling loop. A timeout check on a closed round returns `False`.

Callers may advance without recording attempts. In that case, the transition is recorded, but no per-attempt history exists for that step.

## Storage

For tests or temporary use, pass `InMemoryRoundStore()`. For local JSON persistence, pass a directory to `JsonFileRoundStore`:

```python
from round_management import JsonFileRoundStore, RoundManager

manager = RoundManager(JsonFileRoundStore("dev/temp_outputs/rounds"))
```

The JSON store creates the directory if needed, stores one JSON file per round, checks record revisions to reject stale writes, and uses a lock file while writing. `list_ids()` returns the stored round IDs. Keep disposable development output under `dev/temp_outputs/`.

`verify_integrity()` checks internal consistency among the config fingerprint, transition history, timestamps, attempts, artifacts, and outcome/error fields. It detects accidental or partial inconsistency; it is not cryptographic protection against deliberate edits to the saved record.

## Tests

From `01_orchestrator`, run:

```powershell
python -m unittest discover -s dev/tests -v
```

The tests use in-memory storage, temporary directories, and a fake clock; they do not need live model, platform, Splunk, or judge services.
