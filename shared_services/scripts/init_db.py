"""Provision MongoDB (or the explicit process-local fallback) collections.

Run once (idempotent) to 'start' the database structure:

    python -m shared_services.scripts.init_db

Reads MONGODB_URI from the repository .env, with AUTOSOC_MONGO_URI /
AUTOSOC_DB environment overrides.
"""

from __future__ import annotations

import sys

from pymongo.errors import PyMongoError

from ..config import DB_NAME
from ..datastore.repository import MongoRepository
from ..datastore.schema_registry import available_contracts, missing_contracts, temporary_contracts


def main() -> int:
    repo = None
    try:
        repo = MongoRepository()
        repo.ping()
    except (PyMongoError, RuntimeError) as exc:  # pragma: no cover - environment dependent
        print(
            f"ERROR: MongoDB startup failed ({type(exc).__name__}); "
            "check .env URI, Atlas network access, and credentials.",
            file=sys.stderr,
        )
        if repo is not None:
            repo.close()
        return 1

    try:
        created = repo.ensure_setup()
        print(f"Backend: {repo.backend}")
        if repo.backend == "mongomock":
            print("WARNING: this is temporary process-local data; it is not saved to Atlas.")
        print(f"Database: '{DB_NAME}'")
        print(f"Collections created this run: {created or 'none (already present)'}")
        print(f"Validated messages (schema present):    {available_contracts()}")
        print(f"Temporary schema fallbacks in use:       {temporary_contracts() or 'none'}")
        print(f"Stored-unvalidated (schema pending):     {missing_contracts()}")
    finally:
        repo.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
