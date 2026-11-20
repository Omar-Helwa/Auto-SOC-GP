"""MongoRepository — the datastore boundary for every shared contract.

One collection per contract (see config.ALL_COLLECTIONS). Every write is
validated against the contract's schema first (when one is published); writes
of contract documents that fail validation raise ``ContractViolation`` and are
never stored. Reads strip MongoDB's ``_id`` so returned documents are clean,
re-validatable contract payloads.
"""

from __future__ import annotations

import copy
import logging

from pymongo import ASCENDING, MongoClient

from ..config import ALL_COLLECTIONS, COMMON_INDEX_FIELDS, DB_NAME, MONGO_URI
from . import validation

log = logging.getLogger("autosoc.datastore")


class ContractViolation(Exception):
    """Raised when a document fails its contract schema and is not stored."""


class MongoRepository:
    def __init__(self, uri: str = MONGO_URI, db_name: str = DB_NAME, *, timeout_ms: int = 3000):
        self._client = MongoClient(uri, serverSelectionTimeoutMS=timeout_ms)
        self.db_name = db_name
        self.db = self._client[db_name]

    # -- connection -------------------------------------------------------- #
    def ping(self) -> None:
        """Raise if the server is not reachable."""
        self._client.admin.command("ping")

    def close(self) -> None:
        self._client.close()

    # -- setup ------------------------------------------------------------- #
    def ensure_setup(self) -> list[str]:
        """Create every contract collection and its indexes (idempotent)."""
        existing = set(self.db.list_collection_names())
        created: list[str] = []
        for contract, coll_name in ALL_COLLECTIONS.items():
            if coll_name not in existing:
                self.db.create_collection(coll_name)
                created.append(coll_name)
            coll = self.db[coll_name]
            for fieldname in COMMON_INDEX_FIELDS:
                coll.create_index([(fieldname, ASCENDING)], name=f"ix_{fieldname}")
        return created

    # -- helpers ----------------------------------------------------------- #
    def collection_for(self, contract: str):
        try:
            return self.db[ALL_COLLECTIONS[contract]]
        except KeyError:
            raise KeyError(
                f"Unknown contract '{contract}'. Known: {sorted(ALL_COLLECTIONS)}"
            ) from None

    # -- writes ------------------------------------------------------------ #
    def save(self, contract: str, document: dict, *, validate: bool = True) -> str:
        """Validate (if a schema exists) then insert; return the inserted id."""
        if validate:
            result = validation.validate(document, contract)
            if result is None:
                log.warning(
                    "No schema published for '%s'; storing unvalidated.", contract
                )
            elif not result.ok:
                raise ContractViolation(f"{contract}: {result.summary()}")
        doc = copy.deepcopy(document)  # don't mutate caller; avoid stray _id
        doc.pop("_id", None)
        inserted = self.collection_for(contract).insert_one(doc)
        return str(inserted.inserted_id)

    # -- reads ------------------------------------------------------------- #
    def find(self, contract: str, query: dict | None = None) -> list[dict]:
        cursor = self.collection_for(contract).find(query or {}, {"_id": 0})
        return list(cursor)

    def find_by_task(self, contract: str, task_id: str) -> list[dict]:
        return self.find(contract, {"task_id": task_id})

    def count(self, contract: str, query: dict | None = None) -> int:
        return self.collection_for(contract).count_documents(query or {})
