# Temporary Orchestrator interface schemas

Published schemas in `00_shared_contracts/` and component interface folders
are authoritative. A local schema is used only when the Orchestrator needs a
boundary schema and no shared one exists.

| Local schema | Why it is temporary | Replace/remove when |
|---|---|---|
| `telemetry_evidence.schema.json` | The shared telemetry folder defines `evidence_reference` and `reviewed_label_set`, but not the full evidence envelope currently stored by the Orchestrator. Mongo currently uses this local schema as a fallback too. | A complete shared `telemetry_evidence` schema is published and the repository/Orchestrator use it. |
| `judge_input.schema.json` | There is no shared Judge-input schema. This file validates the Orchestrator's local outer bundle; it does not match the deterministic Judge's current input validator. | Agree on the canonical Judge input and migrate the producer and Judge consumer to it; then remove this local schema. |

The `judge_result` and `feedback_record` messages use the published shared
schemas directly. Blue's evidence view is an internal projection, not a
separate contract; the completed Blue input is validated against Blue's
published schema.

**Current Judge integration blocker:** the local bundle contains
`baseline_match_set`, `candidate_match_set`, `reviewed_label_set`, `criteria`,
and `versions`. The current Judge expects `evaluation_set`, `baseline`,
`candidate`, `reviewed_labels`, `criteria`, and `provenance`, including a full
event inventory and per-event evidence references. These fields cannot all be
derived safely from the current artifacts. The result contract alone does not
define this input handoff.

The validator prefers an available canonical schema over a local fallback.
Do not copy or shadow a published contract schema here.
