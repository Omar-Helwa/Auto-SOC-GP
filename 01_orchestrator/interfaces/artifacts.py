"""Contract-message persistence adapters used by the public interfaces."""

from __future__ import annotations

import copy
import threading
import uuid
from typing import Any, Dict, Mapping, Protocol

from .validation import InterfaceError, copy_message


class ArtifactNotFound(InterfaceError):
    """A stored contract reference cannot be resolved."""


class ArtifactPersistenceError(InterfaceError):
    """A contract artifact read/write failed; dependency failures are retryable."""

    def __init__(self, message: str, *, category: str = "dependency", retryable: bool = True):
        super().__init__(message)
        self.category = category
        self.retryable = retryable


class ContractArtifactStore(Protocol):
    def save(self, contract: str, payload: Mapping[str, Any]) -> str:
        """Persist one contract document and return its stable reference."""

    def load(self, contract: str, reference: str) -> dict:
        """Resolve one previously returned reference to its contract payload."""

    def find_by_task(self, contract: str, task_id: str) -> list[tuple[str, dict]]:
        """Return (reference, payload) pairs for a contract's task_id."""


def save_once(store: ContractArtifactStore, contract: str, payload: Mapping[str, Any]) -> str:
    """Reuse an identical task artifact on retry; otherwise append it once.

    This makes replay after a partial multi-artifact write idempotent without
    changing the immutable contract payload or its Mongo schema.
    """
    task_id = payload.get("task_id")
    try:
        if isinstance(task_id, str) and task_id.strip():
            for reference, existing in store.find_by_task(contract, task_id):
                if existing == dict(payload):
                    return reference
        return store.save(contract, payload)
    except ArtifactPersistenceError:
        raise
    except Exception as exc:
        is_contract_rejection = exc.__class__.__name__ == "ContractViolation"
        is_programmer_error = isinstance(exc, (KeyError, TypeError, ValueError))
        raise ArtifactPersistenceError(
            f"Could not persist {contract} artifact: {exc}",
            category="validation" if is_contract_rejection else "internal" if is_programmer_error else "dependency",
            retryable=not is_contract_rejection and not is_programmer_error,
        ) from exc


class InMemoryArtifactStore:
    """Isolated artifact store for mock rounds and interface tests."""

    def __init__(self) -> None:
        self._documents: Dict[str, tuple[str, dict]] = {}
        self._lock = threading.Lock()

    def save(self, contract: str, payload: Mapping[str, Any]) -> str:
        detached = copy_message(payload)
        reference = f"memory://{contract}/{uuid.uuid4()}"
        with self._lock:
            self._documents[reference] = (contract, detached)
        return reference

    def load(self, contract: str, reference: str) -> dict:
        with self._lock:
            stored = self._documents.get(reference)
            if stored is None or stored[0] != contract:
                raise ArtifactNotFound(f"No {contract} artifact exists at {reference!r}")
            return copy.deepcopy(stored[1])

    def find_by_task(self, contract: str, task_id: str) -> list[tuple[str, dict]]:
        with self._lock:
            rows = [
                (reference, copy.deepcopy(payload))
                for reference, (stored_contract, payload) in self._documents.items()
                if stored_contract == contract and payload.get("task_id") == task_id
            ]
        return rows


class MongoContractArtifactStore:
    """Bridge contract documents to `shared_services.MongoRepository` by duck type.

    The repository's `save()` validates against its mapped shared schema and
    returns a Mongo ObjectId string. Loads resolve that exact ObjectId from the
    same contract collection; no private shared-services module is imported.
    """

    def __init__(self, repository: Any):
        self._repository = repository

    def save(self, contract: str, payload: Mapping[str, Any]) -> str:
        inserted_id = self._repository.save(contract, copy_message(payload))
        return f"mongo://{contract}/{inserted_id}"

    def load(self, contract: str, reference: str) -> dict:
        prefix = f"mongo://{contract}/"
        if not isinstance(reference, str) or not reference.startswith(prefix):
            raise ArtifactNotFound(f"Reference does not identify a Mongo {contract} artifact")
        raw_id = reference[len(prefix):]
        try:
            from bson import ObjectId

            object_id = ObjectId(raw_id)
        except (ImportError, TypeError, ValueError) as exc:
            raise ArtifactNotFound(f"Invalid Mongo artifact reference {reference!r}") from exc
        collection = self._repository.collection_for(contract)
        document = collection.find_one({"_id": object_id}, {"_id": 0})
        if document is None:
            raise ArtifactNotFound(f"No {contract} artifact exists at {reference!r}")
        return copy_message(document)

    def find_by_task(self, contract: str, task_id: str) -> list[tuple[str, dict]]:
        collection = self._repository.collection_for(contract)
        rows = collection.find({"task_id": task_id})
        results = []
        for row in rows:
            document = dict(row)
            object_id = document.pop("_id", None)
            if object_id is None:
                continue
            reference = f"mongo://{contract}/{object_id}"
            results.append((reference, copy_message(document)))
        return results
