"""Connection + collection configuration for the AutoSOC datastore.

All values are environment-overridable so the same code runs against a local
MongoDB, an Atlas cluster, or CI:

    MONGODB_URI         (loaded from the repository .env)
    AUTOSOC_MONGO_URI   (overrides MONGODB_URI)
    AUTOSOC_DB          (default: autosoc)
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env", override=False)

MONGO_URI: str = (
    os.environ.get("AUTOSOC_MONGO_URI")
    or os.environ.get("MONGODB_URI")
    or "mongodb://localhost:27017"
)
DB_NAME: str = os.environ.get("AUTOSOC_DB", "autosoc")

# Shared contract messages (including separately versioned subcontracts),
# each mapped to its MongoDB collection. Stored documents are validated
# against their schema when one is available.
CONTRACT_COLLECTIONS: dict[str, str] = {
    "round_request": "round_requests",
    "red_proposal": "red_proposals",
    "telemetry_evidence": "telemetry_evidence",
    "reviewed_label_set": "reviewed_label_sets",
    "blue_proposal": "blue_proposals",
    "candidate_rule": "candidate_rules",
    "match_set": "match_sets",
    "judge_result": "judge_results",
    "feedback_record": "feedback_records",
    "error_response": "error_responses",
}

# Auxiliary (non-boundary) documents we also persist for audit / replay.
AUX_COLLECTIONS: dict[str, str] = {
    "red_input": "red_inputs",
    "audit_record": "audit_records",
    # Orchestrator round state (one document per round, _id == task_id). Not a
    # contract: written by 01_orchestrator's MongoRoundStore, not by repo.save().
    "round_record": "rounds",
}

ALL_COLLECTIONS: dict[str, str] = {**CONTRACT_COLLECTIONS, **AUX_COLLECTIONS}

# Fields we index on each collection (when present on the documents).
COMMON_INDEX_FIELDS: tuple[str, ...] = ("task_id",)
