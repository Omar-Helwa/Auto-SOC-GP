"""Provision the AutoSOC MongoDB: create every contract collection + indexes.

Run once (idempotent) to 'start' the database structure:

    python -m shared_services.scripts.init_db

Honors AUTOSOC_MONGO_URI / AUTOSOC_DB.
"""

from __future__ import annotations

import sys

from ..config import DB_NAME, MONGO_URI
from ..datastore.repository import MongoRepository
from ..datastore.schema_registry import available_contracts, missing_contracts, temporary_contracts


def main() -> int:
    repo = MongoRepository()
    try:
        repo.ping()
    except Exception as exc:  # pragma: no cover - env dependent
        print(f"ERROR: cannot reach MongoDB at {MONGO_URI}: {exc}", file=sys.stderr)
        return 1

    created = repo.ensure_setup()
    print(f"Connected to {MONGO_URI}, database '{DB_NAME}'.")
    print(f"Collections created this run: {created or 'none (already present)'}")
    print(f"Validated messages (schema present):    {available_contracts()}")
    print(f"Temporary schema fallbacks in use:       {temporary_contracts() or 'none'}")
    print(f"Stored-unvalidated (schema pending):     {missing_contracts()}")
    repo.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
