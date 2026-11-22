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



# Contract: `telemetry_evidence` — reviewed label set

| | |
|---|---|
| **Full contract owner** | Platform (Member 5) |
| **This file** | `reviewed_label_set` — proposed by Orchestrator (Member 1) |
| **Consumers** | Judge (Member 4), Orchestrator (Member 1) |
| **Version** | `0.1.0` |
| **Status** | DRAFT — pending review by Platform (Member 5) and Judge (Member 4) |

Independently reviewed benign/attack labels for every event of one frozen evaluation set, with
provenance. It is the ground truth the deterministic judge compares match sets against. Model claims
are never labels. This file sits next to the `evidence_reference` subset (see `README.md`) and does not
change it. The full `telemetry_evidence` envelope is still Platform's deliverable; this schema can become
its labels section.

Schema: [`reviewed_label_set.schema.json`](reviewed_label_set.schema.json)

## Fields

| Field | Type | Notes |
|-------|------|-------|
| `contract_version` | string (required) | `0.1.0`. |
| `label_set_id` | string (required) | Unique id. |
| `label_set_version` | string (required) | Version of the label set. |
| `dataset` | object (required) | `dataset_id`, `dataset_version`, `evaluation_set_id`, optional `evaluation_set_checksum`. Must match the match sets. |
| `coverage` | object (required) | `total_events` (size of the frozen set) and `complete` (boolean). |
| `labels` | array (required) | One entry per labelled event (below). |

### Label entry

| Field | Type | Notes |
|-------|------|-------|
| `event_id` | string (required) | Same identity as `match_set.matches[].event_id`. |
| `label` | enum (required) | `benign` or `attack`. |
| `source` | enum (required) | `lab_telemetry` or `public_dataset`. |
| `review` | object (required) | `status` (`reviewed`, `disputed`, `unreviewed`), optional `reviewer`, `reviewed_at`. |
| `scenario_id` | string (optional) | Lab scenario or public sample that produced the event. |
| `attack_technique` | string (optional) | MITRE ATT&CK id such as `T1059.001`. |
| `provenance_ref` | string (optional) | Pointer to the immutable evidence record backing the label. |

## Rules

1. Labels cover **all** events of the frozen set, not only matched ones, so lost attack detections can be found.
2. `coverage.complete: true` requires every label to have `review.status: reviewed` (enforced by the schema).
3. Incomplete, disputed, or unreviewed labels make the judge return `inconclusive`, never a pass.
4. Checks JSON Schema cannot express (unique `event_id`, `len(labels)` vs `total_events`) are in
   [`../validation_rules.json`](../validation_rules.json): LS-1, LS-2, LS-3, X-4, X-6.

## Examples

- Valid: [`examples/valid_reviewed_label_set.json`](examples/valid_reviewed_label_set.json)
- Invalid: [`examples/invalid_reviewed_label_set.json`](examples/invalid_reviewed_label_set.json) (reason in `_why_invalid`)