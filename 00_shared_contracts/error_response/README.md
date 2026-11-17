# Contract: `error_response`

| | |
|---|---|
| **Version** | `0.1.0` |
| **Status** | DRAFT — cross-cutting, pending team ratification |
| **Proposed by** | Red role (Member 2) |
| **Consumers** | All components (every boundary may return this) |
| **Review owner** | Team (all members consume it) |

A single error envelope every component can return in place of its success contract, so the
orchestrator handles failures uniformly.

## Required fields

| Field | Type | Notes |
|-------|------|-------|
| `contract_version` | string (semver) | `0.1.0`. |
| `error_id` | string | Unique per occurrence. |
| `category` | enum | `validation`, `missing_information`, `dependency`, `timeout`, `internal`. |
| `source_component` | string | e.g. `02_red_role`. |
| `message` | string | Human-readable; no secrets or raw prompts. |
| `retryable` | boolean | Whether the orchestrator may retry. |

Optional: `task_id`, `details` (machine-readable specifics), `timestamp`.

## How the Red role uses each category

| Category | Red raises it when… | `retryable` |
|----------|---------------------|-------------|
| `missing_information` | required red-input field absent / no usable detection or constraints | `false` |
| `validation` | red input or the parsed model output fails schema validation (malformed proposal) | `false` |
| `dependency` | model gateway (or permitted telemetry source) is unavailable | `true` |
| `timeout` | model gateway exceeds the red time budget | `true` |
| `internal` | unexpected red-side fault | `false` |

> Red never returns a partial or "best effort" proposal. If it cannot produce a contract-valid
> `red_proposal`, it returns a contract-valid `error_response` instead.

## Examples

- Valid: [`examples/valid_error_response.json`](examples/valid_error_response.json)
- Invalid: [`examples/invalid_error_response.json`](examples/invalid_error_response.json) (out-of-enum `category`, missing `source_component`)
