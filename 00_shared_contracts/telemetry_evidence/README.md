# Contract: `telemetry_evidence` — evidence reference (red consumer view)

| | |
|---|---|
| **Full contract owner** | Platform (Member 5) |
| **This file** | `evidence_reference` subset — proposed by Red role (Member 2) |
| **Version** | `0.1.0` |
| **Status** | DRAFT — the full `telemetry_evidence` schema is Member 5's deliverable |

The complete `telemetry_evidence` contract (verified Splunk results, reviewed labels, provenance,
immutable references) is owned and produced by **Platform (Member 5)**. The Red role does **not**
produce evidence and must not embed raw evidence.

What red needs today is only the **reference shape** it is allowed to cite inside a `red_proposal`
(`evidence_references[]`) and receive in its input (`permitted_evidence_refs[]`). That citation-only
subset is defined here in [`evidence_reference.schema.json`](evidence_reference.schema.json) so red
can develop and test independently against mock telemetry.

## Reference fields

| Field | Type | Notes |
|-------|------|-------|
| `evidence_id` | string (required) | Immutable id in the platform evidence store. |
| `evidence_type` | enum (required) | `splunk_result`, `reviewed_label`, `telemetry`. |
| `provenance_ref` | string (optional) | Pointer to source/provenance. |

## Rules

1. A reference is a pointer, never the payload. **Model claims are not evidence.**
2. Red may only cite `evidence_id`s supplied in its input `permitted_evidence_refs`.
3. When Member 5 publishes the full `telemetry_evidence` contract, this subset must remain a strict,
   compatible projection of it — reconcile and bump versions together if the id/type fields change.

## Examples

- Valid: [`examples/valid_evidence_reference.json`](examples/valid_evidence_reference.json)
- Invalid: [`examples/invalid_evidence_reference.json`](examples/invalid_evidence_reference.json) (missing `evidence_id`, out-of-enum `evidence_type`)
