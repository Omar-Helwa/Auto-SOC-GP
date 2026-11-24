# Audit records

The audit writer records immutable round and component-call events. A record
can include the task/round ID, component and state, attempt and transition
sequence, pinned versions, exact input snapshot and artifact references,
output contract versions and references, execution references, raw component
output, validation status, decision, error, and timestamp.

`RoundWorkflow` writes round-opened, component-started, completed, failed, and
round-closed events. Use `MongoAuditRecordStore` with
`create_mongo_workflow()` for durable records. The standalone
`InMemoryAuditRecordStore` is intended for tests and development and is lost
when the process exits. Query the event timeline with
`workflow.audit_writer.store.list_for_round(round_id)`.

Mongo writes use the shared repository's `audit_record` collection mapping.
The shared repository currently has no published audit-record schema, so it
warns and stores these documents without repository-level schema validation.
The Orchestrator checks that audit documents contain required identifiers and
strict JSON values, but a canonical audit schema is still needed.

Raw output is embedded in audit documents when a service supplies it. Define
production size limits, redaction, access, and retention rules before storing
real model responses or sensitive telemetry-derived values. The Orchestrator
does not yet provide a separate archival system for oversized raw outputs.
