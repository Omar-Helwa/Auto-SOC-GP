"""Serialize the Red component's two outputs (Epic G2).

Thin wrappers over schemas.serializer / schemas.errors so every exit path goes
through contract validation. A proposal that would be invalid is downgraded to
an internal error_response rather than emitted.
"""

from __future__ import annotations

from schemas import errors, serializer
from schemas.models import RedProposal


def emit_proposal(proposal: RedProposal) -> dict:
    """Return a validated red_proposal dict, or an internal error if invalid."""
    try:
        return serializer.proposal_to_contract(proposal)
    except serializer.RedContractError as exc:
        return errors.build_error_response(
            "internal",
            f"red produced an invalid proposal: {exc}",
            task_id=proposal.task_id,
        )


def emit_error(category: str, message: str, *, task_id: str | None = None,
               details: dict | None = None) -> dict:
    return errors.build_error_response(
        category, message, task_id=task_id, details=details
    )
