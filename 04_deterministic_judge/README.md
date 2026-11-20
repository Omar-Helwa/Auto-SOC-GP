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

The input is expected to contain:

| Input | Purpose |
|---|---|
| Task identity | Identifies the evaluation task |
| Evaluation-set identity/version | Confirms both executions use the same frozen dataset |
| Baseline rule version | Identifies the original detection rule |
| Candidate rule version | Identifies the proposed detection rule |
| Baseline matches | Events matched by the baseline execution |
| Candidate matches | Events matched by the candidate execution |
| Reviewed labels | Approved benign/attack classifications |
| Criteria | Fixed acceptance criteria for the evaluation |
| Provenance | References to verified evidence, proposals, and executions |

**Note:** Exact field names and schemas are provisional until the shared project contracts are finalized.

## Input Trust and Data Sources

### Red Team

The Red Team provides scenario information and attack context.

Its proposal is not sufficient evidence for the judge to classify an event as an attack.

The platform must verify the evidence and provide reviewed labels.

### Blue Team

The Blue Team provides a proposed rule change.

The judge does not evaluate the proposal description or trust its reported performance.

It evaluates the baseline and candidate match sets produced by platform execution.

### Platform

The platform is responsible for producing or assembling the verified artifacts required by the judge.

The judge does not connect directly to Splunk or execute detection rules.

## Match Comparison

The judge compares normalized match identities.

It must distinguish between:

| Difference | Meaning |
|---|---|
| Retained | Present in both baseline and candidate |
| Removed | Present in baseline but absent from candidate |
| Added | Present in candidate but absent from baseline |
| Lost attack | A removed match classified as an attack |
| Removed benign | A removed match classified as benign |
| New benign | An added match classified as benign |
| New attack | An added match classified as an attack |

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

| Status | Meaning |
|---|---|
| `PASS` | All input and execution checks are valid, and every mandatory gate passes |
| `REJECT` | Evaluation data is valid, but one or more acceptance criteria fail |
| `INCONCLUSIVE` | Required evidence, labels, provenance, or compatible execution artifacts are missing or invalid |

An incomplete evaluation must never produce a PASS.

The orchestrator is responsible for deciding how to handle an INCONCLUSIVE result.

## Project Structure

```text
04_deterministic_judge/
│
├── .gitignore
├── requirements.txt
├── README.md
├── AGENTS.md
├── evaluation/
│   ├── judge.py
│   └── mandatory_gates.py
│
├── match_sets/
│   └── match_processing.py
│
├── metrics/
│   └── metrics.py
│
├── reports/
│   └── report_builder.py
│
├── interfaces/
│   ├── judge_interface.py
│   ├── inputs/
│   │   ├── judge_input.py
│   │   └── input_validator.py
│   └── outputs/
│       ├── judge_result.py
│       └── result_serializer.py
│
├── dev/
│   ├── fixtures/
│   ├── mocks/
│   │   ├── baseline_matches/
│   │   ├── candidate_matches/
│   │   └── reviewed_labels/
│   ├── sandbox/
│   │   └── main.py
│   └── temp_outputs/
│
└── tests/
```

## Component Responsibilities

| Component | Responsibility |
|---|---|
| `main.py` | Local application entry point |
| `evaluation/judge.py` | Coordinates validation, version checks, criteria, metrics, gates, and decision |
| `evaluation/mandatory_gates.py` | Evaluates mandatory acceptance gates |
| `match_sets/match_processing.py` | Normalizes inputs and compares baseline/candidate match identities |
| `metrics/metrics.py` | Defines metric data and calculates all required metrics |
| `reports/report_builder.py` | Builds and saves structured JSON reports |
| `interfaces/judge_interface.py` | Public judge boundary |
| `interfaces/inputs/` | Input model and validation |
| `interfaces/outputs/` | Output model and serialization |
| `dev/fixtures/` | Known-answer test scenarios |
| `dev/mocks/` | Local sample artifacts |
| `dev/sandbox/` | Local execution without external platform services |
| `tests/` | Automated tests |

## Local Setup

### Requirements

- Python 3.10 or newer.
- pip.
- Git.

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

The implementation accepts an assembled JSON object with `evaluation_set.expected_event_ids`,
`baseline`, `candidate`, `reviewed_labels`, explicitly versioned `criteria`, and `provenance`.
Run it directly with:

```powershell
python dev\sandbox\main.py
python dev\sandbox\main.py --input path\to\assembled_judge_input.json
python dev\sandbox\main.py --case case_002
```

The implementation treats `event_id` as the provisional match identity, rejects duplicate
identities, and returns `INCONCLUSIVE` when reviewed labels do not exactly cover the declared
evaluation inventory.

## Running the Sandbox

The sandbox is intended for local development without Splunk or the orchestrator.

From `04_deterministic_judge`:

```powershell
python dev\mocks\generate_mocks.py
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

There are three cases in each directory. Every case has a ten-event inventory and
five available rules. Match identities are selected with a fixed random seed so
the mock data is varied but reproducible:

| Case | Expected result |
|---|---|
| `case_001` | `PASS` |
| `case_002` | `REJECT` because an attack match is lost |
| `case_003` | `REJECT` because a new benign match is introduced |

To save a result instead of printing it:

```powershell
python dev\sandbox\main.py --case case_001 --output dev\temp_outputs\case_001.json
```

Sample artifacts are stored under `dev/mocks/`, and generated temporary reports belong under `dev/temp_outputs/`.

## Running Tests

```bash
pytest
```

Tests must cover:

- Input validation.
- Match normalization and comparison.
- Metric calculations.
- Mandatory gates.
- PASS, REJECT, and INCONCLUSIVE decisions.
- Report generation.
- Deterministic repeated execution.
- End-to-end behavior.

## Development Fixtures

The fixtures should cover:

| Fixture | Expected result |
|---|---|
| Clean improvement | PASS |
| Lost required attack detection | REJECT |
| New benign match introduced | REJECT |
| Missing reviewed label | INCONCLUSIVE |
| Missing required evidence | INCONCLUSIVE |
| Different evaluation-set versions | INCONCLUSIVE |
| Invalid execution artifact | INCONCLUSIVE |
| Repeated identical input | Identical output |

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

## Current Contract Status

The architecture and responsibilities are defined, but the exact input and output JSON structures remain provisional.

Before integration, the team must agree on:

- Stable match identity.
- Evaluation-set identity and version.
- Reviewed-label structure and provenance.
- Baseline and candidate execution metadata.
- Criteria structure and version.
- Judge result structure.
- Failure reason and gate vocabulary.

Do not independently redefine fields owned by the shared contracts.

## Definition of Done

The component is ready for integration when:

- The shared input and output contracts are finalized.
- All required artifacts are validated.
- Match comparisons are correct and deterministic.
- Metrics are calculated correctly.
- Mandatory gates are enforced.
- All three decision statuses work correctly.
- Every decision is explainable.
- Reports preserve exact differences and provenance.
- Tests cover normal, rejected, and inconclusive cases.
- The judge runs locally without external platform dependencies.