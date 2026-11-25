# Orchestrator-local contract schemas

Schemas in `00_shared_contracts/` and component interface folders are
authoritative. The Orchestrator uses a local schema only where no shared
contract defines the boundary.

| Local schema | Why it is temporary | Replace/remove when |
|---|---|---|
| `telemetry_evidence.schema.json` | The shared telemetry folder publishes evidence references and reviewed labels, but not the complete telemetry evidence envelope persisted by the Orchestrator. | A complete shared telemetry evidence schema is published and used by the Platform, Orchestrator, and repository. |

`judge_input`, `judge_result`, and `feedback_record` use their published shared
schemas. Blue's evidence projection is internal; the completed `blue_input`
is validated against the Blue component's public schema.

The validator prefers canonical schemas over local fallbacks. Do not copy or
shadow a published contract schema here.
