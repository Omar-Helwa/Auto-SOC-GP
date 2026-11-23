"""MongoDB round store: the durable home for round records.

One document per round in a ``rounds`` collection, with ``_id`` equal to the
round id (the ``task_id``). MongoDB guarantees ``_id`` is unique, so a round can
be created once, and every update is a single atomic compare-and-set on the
revision:

    replace_one({"_id": round_id, "revision": <revision you loaded>}, new_document)

If someone else saved first the filter matches nothing and ``save`` raises
``ConcurrencyError``. There are no lock files and no cross-process locking code.

The collection is provisioned by ``python -m shared_services.scripts.init_db``
(it is ``rounds`` in ``shared_services/config.py``). Round state is not a
contract, so it is written here and not through ``MongoRepository.save``.
Messages that components return still go to their contract collections through
``MongoRepository``; a round records only references to them.

``pymongo`` is imported lazily so the rest of ``round_management`` keeps working
without it. Pass a collection created with the write concern you want, for
example ``db["rounds"].with_options(write_concern=WriteConcern(w="majority"))``.
"""

from __future__ import annotations

import json
from typing import Any, Callable, List, Optional

from .contracts import TASK_ID_PATTERN
from .errors import ConcurrencyError, IntegrityError, RoundManagementError, StoreUnavailableError
from .models import RoundRecord
from .store import RoundStore

try:  # pragma: no cover - exercised implicitly
    from bson.errors import BSONError
    from pymongo.errors import DuplicateKeyError, PyMongoError, WriteError

    _HAVE_PYMONGO = True
except ImportError:  # pragma: no cover
    _HAVE_PYMONGO = False

    class BSONError(Exception):  # type: ignore[no-redef]
        pass

    class PyMongoError(Exception):  # type: ignore[no-redef]
        pass

    class WriteError(PyMongoError):  # type: ignore[no-redef]
        pass

    class DuplicateKeyError(WriteError):  # type: ignore[no-redef]
        pass


DEFAULT_COLLECTION = "rounds"


class MongoRoundStore(RoundStore):
    def __init__(self, collection: Any) -> None:
        if not _HAVE_PYMONGO:
            raise RoundManagementError("MongoRoundStore needs pymongo: pip install -r requirements.txt")
        self._coll = collection

    @classmethod
    def from_repository(cls, repo: Any, collection_name: str = DEFAULT_COLLECTION) -> "MongoRoundStore":
        """Use the database a ``shared_services`` ``MongoRepository`` is connected to."""
        return cls(repo.db[collection_name])

    def ensure_indexes(self) -> None:
        """Create the lookup indexes (``init_db`` creates the collection and ``task_id`` index too)."""
        self._call(self._coll.create_index, [("task_id", 1)], name="ix_task_id")
        self._call(self._coll.create_index, [("state", 1)], name="ix_state")

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _check_id(round_id: Any) -> None:
        if not isinstance(round_id, str) or not TASK_ID_PATTERN.match(round_id):
            raise RoundManagementError(f"Unsafe round id: {round_id!r}")

    @staticmethod
    def _unavailable(exc: Exception) -> StoreUnavailableError:
        return StoreUnavailableError(
            f"MongoDB operation failed: {exc.__class__.__name__}",
            {"error_type": exc.__class__.__name__, "error": str(exc)[:300]},
        )

    def _call(self, fn: Callable, *args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except PyMongoError as exc:
            raise self._unavailable(exc) from exc

    # --------------------------------------------------------------- interface
    def load(self, round_id: str) -> Optional[RoundRecord]:
        self._check_id(round_id)
        doc = self._call(self._coll.find_one, {"_id": round_id})
        if doc is None:
            return None
        data = dict(doc)
        data.pop("_id", None)
        data.pop("task_id", None)  # storage-only field used for indexing
        try:
            return RoundRecord.from_dict(data)
        except (KeyError, TypeError, ValueError, RoundManagementError) as exc:
            raise IntegrityError(f"Round {round_id}: stored document is not a valid round record") from exc

    def save(self, record: RoundRecord) -> None:
        self._check_id(record.round_id)
        data = record.to_dict()
        data["revision"] = record.revision + 1
        try:
            json.dumps(data, allow_nan=False)  # BSON would accept NaN; keep the record strict JSON
        except (TypeError, ValueError) as exc:
            raise IntegrityError(f"Round {record.round_id}: record is not valid JSON") from exc
        document = dict(data)
        document["_id"] = record.round_id
        document["task_id"] = record.config.task_id
        try:
            if record.revision == 0:
                self._coll.insert_one(document)
            else:
                result = self._coll.replace_one(
                    {"_id": record.round_id, "revision": record.revision}, document
                )
                if result.matched_count != 1:
                    raise ConcurrencyError(
                        f"Round {record.round_id} changed or was never stored "
                        f"(yours: revision {record.revision}); reload and retry"
                    )
        except ConcurrencyError:
            raise
        except DuplicateKeyError as exc:
            raise ConcurrencyError(f"Round {record.round_id} already exists") from exc
        except (BSONError, OverflowError, WriteError) as exc:
            raise IntegrityError(f"Round {record.round_id}: MongoDB rejected the document: {exc}") from exc
        except PyMongoError as exc:
            raise self._unavailable(exc) from exc
        record.revision += 1

    def list_ids(self) -> List[str]:
        rows = self._call(lambda: list(self._coll.find({}, {"_id": 1})))
        return sorted(row["_id"] for row in rows)
