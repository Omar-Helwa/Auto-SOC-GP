"""Connection + collection configuration for the AutoSOC datastore.

All values are environment-overridable so the same code runs against a local
MongoDB, a teammate's instance, or CI:

    AUTOSOC_MONGO_URI   (default: mongodb://localhost:27017)
    AUTOSOC_DB          (default: autosoc)
"""

from __future__ import annotations

import os

MONGO_URI: str = os.environ.get("AUTOSOC_MONGO_URI", "mongodb://localhost:27017")
DB_NAME: str = os.environ.get("AUTOSOC_DB", "autosoc")

# The eight shared contracts, each mapped to its MongoDB collection.
# A document stored under a contract name lands in its collection and is
# validated against that contract's schema (when a schema exists).
CONTRACT_COLLECTIONS: dict[str, str] = {
    "round_request": "round_requests",
    "red_proposal": "red_proposals",
    "telemetry_evidence": "telemetry_evidence",
    "blue_proposal": "blue_proposals",
    "candidate_rule": "candidate_rules",
    "judge_result": "judge_results",
    "feedback_record": "feedback_records",
    "error_response": "error_responses",
}

# Auxiliary (non-boundary) documents we also persist for audit / replay.
AUX_COLLECTIONS: dict[str, str] = {
    "red_input": "red_inputs",
}

ALL_COLLECTIONS: dict[str, str] = {**CONTRACT_COLLECTIONS, **AUX_COLLECTIONS}

# Fields we index on each collection (when present on the documents).
COMMON_INDEX_FIELDS: tuple[str, ...] = ("task_id",)
