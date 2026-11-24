"""Serialize models to validated, contract-valid output.

The only functions the rest of the Blue component should use to produce its
outputs. Each validates against the schema first, so Blue cannot emit a
payload that violates its own contract.
"""

from __future__ import annotations

import json

from . import validation
from .errors import BlueContractError, build_error_response
from .models import BlueProposal


def proposal_to_contract(proposal: BlueProposal) -> dict:
    payload = proposal.to_dict()
    result = validation.validate_blue_proposal(payload)
    if not result.ok:
        raise BlueContractError(f"Refusing to emit invalid blue_proposal: {result.summary()}")
    return payload


def error_to_contract(error_payload: dict) -> dict:
    result = validation.validate_error_response(error_payload)
    if not result.ok:
        raise BlueContractError(f"Refusing to emit invalid error_response: {result.summary()}")
    return error_payload


def to_json(payload: dict, *, indent: int | None = 2) -> str:
    return json.dumps(payload, indent=indent, ensure_ascii=False)


__all__ = ["proposal_to_contract", "error_to_contract", "to_json", "build_error_response", "BlueContractError"]
