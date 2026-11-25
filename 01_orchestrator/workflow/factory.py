"""Composition helpers for wiring workflow services to orchestrator storage."""

from __future__ import annotations

from typing import Any, Optional

from interfaces.artifacts import MongoContractArtifactStore
from interfaces.inputs import OrchestratorInputAdapter
from interfaces.outputs import OrchestratorOutputAdapter
from interfaces.validation import InterfaceValidator
from round_management import MongoRoundStore, RoundManager
from audit_records import AuditRecordWriter, MongoAuditRecordStore

from .runner import RoundWorkflow


def create_workflow(
    round_store: Any,
    artifact_store: Any,
    services: Any,
    *,
    validator: Optional[InterfaceValidator] = None,
    audit_writer: Optional[AuditRecordWriter] = None,
    allow_non_mongo_stores: bool = False,
) -> RoundWorkflow:
    """Build a complete workflow over supplied round/artifact stores.

    Both adapters share one manager and artifact store so state transitions and
    contract references remain consistent. Non-Mongo stores require an
    explicit opt-in for development and tests; production wiring should use
    ``create_mongo_workflow``.
    """
    is_mongo_wired = isinstance(round_store, MongoRoundStore) and isinstance(
        artifact_store, MongoContractArtifactStore
    )
    if not is_mongo_wired and not allow_non_mongo_stores:
        raise ValueError(
            "Non-Mongo workflow stores are disabled by default; pass "
            "allow_non_mongo_stores=True for development/tests or use create_mongo_workflow()"
        )
    manager = RoundManager(round_store)
    inputs = OrchestratorInputAdapter(manager, artifact_store, validator)
    outputs = OrchestratorOutputAdapter(manager, artifact_store, validator)
    return RoundWorkflow(inputs, outputs, services, audit_writer=audit_writer)


def create_mongo_workflow(repository: Any, services: Any, *, validator: Optional[InterfaceValidator] = None) -> RoundWorkflow:
    """Wire Mongo round records and contract artifacts to a shared repository."""
    ensure_setup = getattr(repository, "ensure_setup", None)
    if callable(ensure_setup):
        ensure_setup()
    round_store = MongoRoundStore.from_repository(repository)
    round_store.ensure_indexes()
    artifact_store = MongoContractArtifactStore(repository)
    audit_writer = AuditRecordWriter(MongoAuditRecordStore(repository))
    return create_workflow(
        round_store, artifact_store, services, validator=validator, audit_writer=audit_writer
    )

