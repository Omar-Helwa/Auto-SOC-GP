# AutoSOC Architecture 1

This repository implements the Architecture 1 detection-improvement workflow.
Shared contracts define component boundaries; the Orchestrator owns the round
order and state; Platform integrations own approved external operations; and
the deterministic Judge alone returns the acceptance decision.

## Folder ownership

| Folder | Responsibility |
|---|---|
| [`00_shared_contracts/`](00_shared_contracts/) | Versioned JSON contracts, schemas, examples, and validation rules shared across components. |
| [`01_orchestrator/`](01_orchestrator/) | Frozen round configuration, required state transitions, retries, audit, artifact validation, and feedback. |
| [`02_red_role/`](02_red_role/) | Produces a bounded benign scenario proposal; it does not execute it or decide acceptance. |
| [`03_blue_role/`](03_blue_role/) | Produces a constrained detection-rule edit proposal; it does not compile or execute the candidate. |
| [`04_deterministic_judge/`](04_deterministic_judge/) | Validates evidence, calculates evaluation metrics, and returns PASS, REJECT, or INCONCLUSIVE. |
| [`05_platform_integrations/`](05_platform_integrations/) | Model, validation, Splunk, labelled-data, and evidence-store adapters behind shared interfaces. |
| [`99_integration/`](99_integration/) | Application composition and end-to-end adapters. This layer wires services; it does not own workflow policy. |
| [`shared_services/`](shared_services/) | Cross-component MongoDB persistence and the public `RoundController` facade. |

`shared_services.controller.RoundController` is the application's entry point
for Mongo-backed rounds. It delegates to `01_orchestrator/workflow`; there is
only one implementation of round ordering, retry policy, audit, and feedback.
Orchestrator interfaces use a namespaced Python import so Red's own `interfaces`
package can coexist in one process.

## Round data flow

```text
round_request
    -> Orchestrator opens and freezes the round
    -> Red proposes a benign scenario
    -> Platform validates and executes the approved operation
    -> Platform verifies telemetry, labels, and baseline evidence
    -> Blue proposes a rule edit from the verified evidence
    -> Platform validates, compiles, and executes the candidate
    -> Judge evaluates the shared evidence bundle
    -> Orchestrator stores feedback and closes the round
```

Each component may reject malformed or out-of-scope input at its boundary.
Only Platform executes approved operations; only the Judge returns an
acceptance decision. The Orchestrator enforces order and records state but does
not author Red/Blue proposals or decide whether a candidate passes.

The assembled runner in `99_integration/assembled_runs/` composes the real
Red, Blue, Platform (approval-gated Splunk searches), and Judge components.
It requires a frozen, human-reviewed evaluation set indexed in Splunk, Splunk
over verified TLS, and persistent MongoDB. Its tests use a local Splunk stub
and `mongomock`. See
[`99_integration/assembled_runs/README.md`](99_integration/assembled_runs/README.md)
for setup, the mock/live boundary, and current limitations.

## Development

Component-specific setup, mock scenarios, and test commands are documented in
each numbered folder. Run from the repository root for shared-service tests:

```powershell
python -m pytest shared_services/tests
```

The Orchestrator's focused test suite can be run with:

```powershell
Set-Location 01_orchestrator
python -m unittest discover -s dev/tests -v
```
