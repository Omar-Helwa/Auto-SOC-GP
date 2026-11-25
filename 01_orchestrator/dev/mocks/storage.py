"""Deterministic storage fault used to exercise partial-write recovery."""

from __future__ import annotations

from typing import Any, Mapping

from orchestrator_interfaces.artifacts import ArtifactPersistenceError


class FailOnceArtifactStore:
    """Raise once before delegating a save for the selected contract."""

    def __init__(self, store: Any, contract: str = "reviewed_label_set"):
        self.store = store
        self.contract = contract
        self.failed = False
        self.save_attempts: dict[str, int] = {}

    def save(self, contract: str, payload: Mapping[str, Any]) -> str:
        self.save_attempts[contract] = self.save_attempts.get(contract, 0) + 1
        if contract == self.contract and not self.failed:
            self.failed = True
            raise ArtifactPersistenceError(
                f"simulated one-time {contract} storage interruption",
                category="dependency",
                retryable=True,
            )
        return self.store.save(contract, payload)

    def load(self, contract: str, reference: str) -> dict:
        return self.store.load(contract, reference)

    def find_by_task(self, contract: str, task_id: str) -> list[tuple[str, dict]]:
        return self.store.find_by_task(contract, task_id)
