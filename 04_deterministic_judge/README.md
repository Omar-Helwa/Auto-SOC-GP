# Deterministic Judge

## Overview

The **Deterministic Judge** is the independent evaluation component of the AutoSOC project.

Its purpose is to determine whether a candidate detection-rule version improves on the baseline version without violating the project's attack-detection requirements.

It compares platform-produced baseline and candidate match sets against reviewed labels from the same frozen evaluation set.

The judge calculates evaluation metrics, checks mandatory acceptance criteria, and produces a reproducible decision.

The judge does not use an LLM and does not trust Red Team or Blue Team self-reported results.

## Responsibilities

The judge is responsible for:

- Validating evaluation input.
- Checking artifact and version compatibility.
- Normalizing match sets and reviewed labels.
- Comparing baseline and candidate match identities.
- Identifying retained, removed, and added matches.
- Identifying lost attack detections and new benign matches.
- Calculating evaluation metrics.
- Applying mandatory acceptance gates.
- Producing PASS, REJECT, or INCONCLUSIVE.
- Generating structured JSON reports.
- Preserving provenance and exact failure reasons.

## What the Judge Receives

The judge receives one assembled evaluation input from the platform or its adapter.

The input is one JSON object:

| Field | Contract | Purpose |
|---|---|---|
| `judge_input_id` | string | Identifies this evaluation |
| `baseline` | `00_shared_contracts/candidate_rule/match_set.schema.json` (`role: baseline`) | Events matched by the original rule |
| `candidate` | same schema (`role: candidate`, `candidate_ref` required) | Events matched by the candidate rule |
| `reviewed_labels` | `00_shared_contracts/telemetry_evidence/reviewed_label_set.schema.json` | Reviewed labels for every event of the frozen set |
| `criteria` | judge-owned: `criteria_id`, `criteria_version`, `minimum_attack_retention`, `maximum_new_benign_matches` | Fixed acceptance criteria |

Task, detection, rule versions, dataset, and execution provenance are read from the artifacts themselves.

Each artifact is validated against its shared schema. Schemas are loaded from `00_shared_contracts/`
by `$id`; override the folder with `AUTOSOC_CONTRACTS_DIR`. The judge then applies the rules in
`00_shared_contracts/validation_rules.json` that JSON Schema cannot express: MS-1, LS-1, LS-2,
LS-3, X-1 (kind `invalid`) and X-2, X-4, X-5, X-6 (kind `incomplete`). X-3 needs the
`candidate_rule` artifact and is left to the Orchestrator. Any failure returns `INCONCLUSIVE`,
with each failure listed in `decision.failures` as `{code, kind, message}`.

## Match Comparison

The judge compares normalized match identities.

It must distinguish between:

| Difference     | Meaning                                       |
| -------------- | --------------------------------------------- |
| Retained       | Present in both baseline and candidate        |
| Removed        | Present in baseline but absent from candidate |
| Added          | Present in candidate but absent from baseline |
| Lost attack    | A removed match classified as an attack       |
| Removed benign | A removed match classified as benign          |
| New benign     | An added match classified as benign           |
| New attack     | An added match classified as an attack        |

Classification is based on reviewed labels, not on match names or role descriptions.

## Metrics

The judge calculates metrics for both baseline and candidate executions.

Expected metrics include:

- True positives (TP)
- False positives (FP)
- True negatives (TN)
- False negatives (FN)
- Precision
- Recall
- Accuracy
- F1 score
- False-positive reduction
- Attack retention
- Lost attack detections
- New benign matches
- Changes in relevant metrics

All metrics are calculated by the judge from the match sets and reviewed labels.

Role-provided metric summaries must not be used as the source of truth.

## Mandatory Gates

The initial implementation includes:

### 1. Attack Retention

Checks whether the candidate retains the required attack detections.

Controlled by the fixed `minimum_attack_retention` criterion.

### 2. New Benign Matches

Checks whether the candidate introduces additional matches on reviewed benign events.

Controlled by `maximum_new_benign_matches`.

### 3. Evidence Completeness

Checks that required labels, evidence, and provenance are available and valid.

### 4. Execution Validity

Checks that baseline and candidate executions completed successfully and are comparable.

Additional gates must be agreed through the shared project contract.

## Decision Results

The judge returns one of three statuses.

| Status         | Meaning                                                                                         |
| -------------- | ----------------------------------------------------------------------------------------------- |
| `PASS`         | All input and execution checks are valid, and every mandatory gate passes                       |
| `REJECT`       | Evaluation data is valid, but one or more acceptance criteria fail                              |
| `INCONCLUSIVE` | Required evidence, labels, provenance, or compatible execution artifacts are missing or invalid |

An incomplete evaluation must never produce a PASS.

The orchestrator is responsible for deciding how to handle an INCONCLUSIVE result.

## Project Structure
```text
04_deterministic_judge/
├── .gitignore
├── README.md
├── evaluation/
│   ├── judge.py                  # compares, measures, applies gates, decides
│   └── mandatory_gates.py        # attack_retention and new_benign_matches gates
├── match_sets/
│   └── match_processing.py       # indexes by event_id, computes match differences
├── metrics/
│   └── metrics.py                # TP/FP/TN/FN, precision, recall, accuracy, F1
├── reports/
│   └── report_builder.py         # builds the PASS/REJECT judge_result body
├── interfaces/
│   ├── inputs/
│   │   └── judge_input.py        # run_judge, validate_judge_input, shared-schema loading
│   └── outputs/
│       └── judge_result.py       # save_output
├── outputs/                      # saved judge results (created on first save, git-ignored)
└── dev/
    ├── fixtures/
    ├── in_out_structure/         # reference input and output shapes
    │   ├── Judge Input.json      # judge_input bundle schema
    │   ├── baseline_matches.json
    │   ├── candidate_matches.json
    │   ├── reviewed_labels.json
    │   └── judge_output.json
    ├── mocks/                    # case_001 to case_004 in each folder
    │   ├── baseline_matches/
    │   ├── candidate_matches/
    │   └── reviewed_labels/
    ├── sandbox/
    │   └── main.py               # builds a bundle from a mock case and runs the judge
    └── temp_outputs/             # sandbox results (git-ignored)
```

The shared schemas the judge validates against live outside this folder, in
`00_shared_contracts/` (`judge_input`, `judge_result`, `candidate_rule/match_set`,
`telemetry_evidence/reviewed_label_set`, `validation_rules.json`).

## Component Responsibilities

| Component                        | Responsibility                                                                 |
| -------------------------------- | ------------------------------------------------------------------------------ |
| `main.py`                        | Local application entry point                                                  |
| `evaluation/judge.py`            | Coordinates validation, version checks, criteria, metrics, gates, and decision |
| `evaluation/mandatory_gates.py`  | Evaluates mandatory acceptance gates                                           |
| `match_sets/match_processing.py` | Normalizes inputs and compares baseline/candidate match identities             |
| `metrics/metrics.py`             | Defines metric data and calculates all required metrics                        |
| `reports/report_builder.py`      | Builds and saves structured JSON reports                                       |
| `interfaces/judge_interface.py`  | Public judge boundary                                                          |
| `interfaces/inputs/`             | Input model and validation                                                     |
| `interfaces/outputs/`            | Output model and serialization                                                 |
| `dev/fixtures/`                  | Known-answer test scenarios                                                    |
| `dev/mocks/`                     | Local sample artifacts                                                         |
| `dev/sandbox/`                   | Local execution without external platform services                             |
| `tests/`                         | Automated tests                                                                |

## Local Setup

### Requirements

- Python 3.10 or newer.
- pip.

The judge should run independently of Splunk and the orchestrator.

### 1. Clone the project

Navigate to the `04_deterministic_judge` directory.

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

The implementation accepts an assembled JSON object with `judge_input_id`, `baseline`,
`candidate`, `reviewed_labels`, and explicitly versioned `criteria` (see "What the Judge Receives").
Run it directly with:

```powershell
python dev\sandbox\main.py
python dev\sandbox\main.py --input path\to\assembled_judge_input.json
python dev\sandbox\main.py --case case_002
```

The implementation uses `event_id` as the match identity shared by match sets and labels.
The reviewed label set defines the frozen evaluation inventory, so it must be complete
(`coverage.complete: true`, every label `review.status: reviewed`).

## Running the Sandbox

The sandbox is intended for local development without Splunk or the orchestrator.

From `04_deterministic_judge`:

```powershell
python dev\sandbox\main.py --case case_001
```

The sandbox `main.py` runner uses the public judge interface and assembles
the selected baseline, candidate, and reviewed-label artifacts into one judge input.
When `--output` is omitted, the result is also saved as
`dev\temp_outputs\<case>.json`; passing `--output` overrides that output path.
The generated cases are deterministic and stored under:

- `dev/mocks/baseline_matches/`
- `dev/mocks/candidate_matches/`
- `dev/mocks/reviewed_labels/`

There are four cases in each directory, all following the shared `match_set` and
`reviewed_label_set` 0.1.0 contracts. Every case has a ten-event evaluation set:

| Case | Expected result |
|---|---|
| `case_001` | `PASS` |
| `case_002` | `REJECT` because an attack match is lost |
| `case_003` | `REJECT` because a new benign match is introduced |
| `case_004` | `INCONCLUSIVE`: candidate execution is `partial`, coverage is incomplete, one label is `disputed` |

To save a result instead of printing it:

```powershell
python dev\sandbox\main.py --case case_001 --output dev\temp_outputs\case_001.json
```

Sample artifacts are stored under `dev/mocks/`, and generated temporary reports belong under `dev/temp_outputs/`.

## Design Constraints

- No LLM calls.
- No direct Splunk connection.
- No direct rule execution.
- No direct orchestrator dependency.
- No reliance on Red Team or Blue Team self-reported metrics.
- No inferred missing labels.
- No mutable acceptance criteria during evaluation.
- No silent fallback for invalid input.
- No unnecessary dependencies or abstractions.
- Stable ordering and reproducible output.

## Integration Boundary

The Orchestrator calls `run_judge(bundle)` and gets the `judge_result` back as the return value:

```python
from interfaces.inputs.judge_input import run_judge, validate_judge_input
from interfaces.outputs.judge_result import save_output

result = run_judge(bundle)             # bundle follows 00_shared_contracts/judge_input/judge_input.schema.json
save_output(result)                    # writes outputs/<judge_input_id>.json (override with JUDGE_OUTPUT_DIR)
validate_judge_input(bundle)           # list of {code, kind, message}; empty means the bundle can be judged
```

| File | Functions |
|---|---|
| `interfaces/inputs/judge_input.py` | `run_judge`, `validate_judge_input` |
| `interfaces/outputs/judge_result.py` | `save_output` |


The intended integration flow is:

```text
Platform execution
       |
       v
Artifact verification
       |
       v
Judge input assembly
       |
       v
Public judge interface
       |
       v
Deterministic evaluation
       |
       v
Structured judge result
       |
       v
Orchestrator
```

The orchestrator owns round state, retries, and policy for inconclusive evaluations.

The judge owns deterministic evaluation only.

