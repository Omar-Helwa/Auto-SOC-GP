"""B4 (part 2) — serialize models to validated, contract-valid output.

These are the only functions the rest of the Red component should use to
produce its two outputs. Each one validates against the schema before
returning, so it is impossible for Red to emit a payload that violates its
own contract: on failure it raises ``RedContractError`` (a red-side bug) which
the interface layer turns into an ``internal`` error_response.
"""

from __future__ import annotations

import json

from . import validation
from .errors import RedContractError, build_error_response
from .models import RedProposal


def proposal_to_contract(proposal: RedProposal) -> dict:
    """Return a validated ``red_proposal`` dict, or raise RedContractError."""
    payload = proposal.to_dict()
    result = validation.validate_red_proposal(payload)
    if not result.ok:
        raise RedContractError(
            f"Refusing to emit invalid red_proposal: {result.summary()}"
        )
    return payload


def error_to_contract(error_payload: dict) -> dict:
    """Validate an already-built error_response dict before returning it."""
    result = validation.validate_error_response(error_payload)
    if not result.ok:
        raise RedContractError(
            f"Refusing to emit invalid error_response: {result.summary()}"
        )
    return error_payload


def to_json(payload: dict, *, indent: int | None = 2) -> str:
    """Serialize a validated payload dict to a JSON string."""
    return json.dumps(payload, indent=indent, ensure_ascii=False)


# Re-exported so callers can `from schemas.serializer import build_error_response`.
__all__ = [
    "proposal_to_contract",
    "error_to_contract",
    "to_json",
    "build_error_response",
    "RedContractError",
]
