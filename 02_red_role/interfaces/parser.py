"""Parse a raw model response into a RedProposal (Epic F4).

The model returns only the *creative* part (scenario + justification). This
parser assembles a full, controlled RedProposal by combining that with fields
the component owns and must not let the model invent: task_id, prompt_version,
detection_under_test (from the input), a fresh proposal_id, the pinned
contract_version, and the constraints acknowledgement. Malformed JSON or a
refusal raise a ParseError the caller maps to a validation error_response.
"""

from __future__ import annotations

import json
import re
import uuid

from schemas.models import (
    ConstraintsAck,
    DetectionUnderTest,
    EvidenceReference,
    RedInput,
    RedProposal,
    Scenario,
)

_REFUSAL_MARKERS = (
    "i cannot", "i can't", "i'm sorry", "i am sorry",
    "cannot help", "as an ai", "i won't", "i will not",
)


class ParseError(Exception):
    """Raised when the model output cannot be turned into a valid proposal."""


def _looks_like_refusal(text: str) -> bool:
    low = text.strip().lower()
    return any(m in low for m in _REFUSAL_MARKERS)


def _extract_json(text: str) -> dict:
    text = text.strip()
    # tolerate ```json ... ``` fences
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"model output is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError("model output JSON is not an object")
    return data


def parse_proposal(raw_text: str, red_input: RedInput, prompt_version: str) -> RedProposal:
    if _looks_like_refusal(raw_text):
        raise ParseError("model refused to produce a proposal")

    data = _extract_json(raw_text)
    if "scenario" not in data:
        raise ParseError("model output missing 'scenario'")

    try:
        scenario = Scenario.from_dict(data["scenario"])
    except (KeyError, TypeError) as exc:
        raise ParseError(f"malformed scenario: {exc}") from exc

    benign_justification = data.get("benign_justification")
    if not benign_justification:
        raise ParseError("model output missing 'benign_justification'")

    evidence_refs = data.get("evidence_references", [])
    if not isinstance(evidence_refs, list):
        raise ParseError("model output 'evidence_references' must be an array")
    try:
        evidence = [EvidenceReference.from_dict(ref) for ref in evidence_refs]
    except (KeyError, TypeError) as exc:
        raise ParseError(f"malformed evidence reference: {exc}") from exc

    return RedProposal(
        proposal_id=str(uuid.uuid4()),
        task_id=red_input.task_id,
        prompt_version=prompt_version,
        detection_under_test=DetectionUnderTest(
            detection_id=red_input.detection.detection_id,
            rule_version=red_input.detection.rule_version,
        ),
        scenario=scenario,
        benign_justification=benign_justification,
        evidence_references=evidence,
        constraints_ack=ConstraintsAck(),  # all True by construction
        rationale=data.get("rationale"),
    )
