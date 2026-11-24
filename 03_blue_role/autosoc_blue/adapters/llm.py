"""LLM proposer: asks a ModelGateway for a JSON edit proposal.

The model only suggests structured edits. They are normalised and pre-flight
checked by the engine like any other draft; on a rejection the engine calls
this proposer once more with the failure reasons.
"""

from __future__ import annotations

import json
import re
from typing import Sequence

from ..core.context import BlueContext
from ..core.draft import Draft
from ..ports import ModelGateway, ModelTimeout, ModelUnavailable, ProposerError
from ..prompts import registry
from ..schemas.models import FieldCondition, RuleEdit

_FENCE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$")


def extract_json_object(text: str) -> dict:
    """Pull the first JSON object out of a model answer (tolerates code fences / chatter)."""
    if not isinstance(text, str) or not text.strip():
        raise ProposerError("the model returned an empty answer")
    cleaned = _FENCE.sub("", text.strip())
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        if start < 0:
            raise ProposerError("the model answer contains no JSON object") from None
        try:
            value, _ = json.JSONDecoder().raw_decode(cleaned[start:])
        except json.JSONDecodeError as exc:
            raise ProposerError(f"the model answer is not valid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ProposerError("the model answer is not a JSON object")
    return value


def parse_draft(text: str) -> Draft:
    data = extract_json_object(text)
    raw_edits = data.get("edits")
    if not isinstance(raw_edits, list) or not raw_edits:
        raise ProposerError("the model answer has no 'edits' list")
    edits: list[RuleEdit] = []
    for n, raw in enumerate(raw_edits):
        try:
            conditions = [
                FieldCondition(str(c["field"]), str(c["modifier"]), [str(v) for v in c["values"]])
                for c in raw["conditions"]
            ]
            edits.append(RuleEdit(
                str(raw["operation"]), conditions, str(raw.get("reason") or ""),
                raw.get("target_selection") or None,
            ))
        except (KeyError, TypeError) as exc:
            raise ProposerError(f"edit {n} is malformed: {type(exc).__name__} {exc}") from exc
    addressed = data.get("addressed_false_positives") or []
    if not isinstance(addressed, list):
        raise ProposerError("'addressed_false_positives' must be a list")
    return Draft(
        edits=edits,
        addressed_false_positives=[str(a) for a in addressed],
        justification=str(data.get("justification") or ""),
        expected_effect=(str(data["expected_effect"]) if data.get("expected_effect") else None),
        rationale=(str(data["rationale"]) if data.get("rationale") else None),
        source="llm",
    )


class LLMProposer:
    name = "llm"
    uses_feedback = True

    def __init__(self, gateway: ModelGateway, *, model_params: dict | None = None):
        self.gateway = gateway
        self.model_params = model_params or {}

    def propose(self, ctx: BlueContext, feedback: Sequence[str] = ()) -> Draft:
        prompt = registry.render(ctx.input.prompt_version, ctx, list(feedback))
        try:
            response = self.gateway.generate(prompt["system"], prompt["task"], self.model_params)
        except ModelTimeout as exc:
            raise ProposerError(f"model timed out: {exc}") from exc
        except ModelUnavailable as exc:
            raise ProposerError(f"model unavailable: {exc}") from exc
        draft = parse_draft(response.text)
        draft.source = f"llm:{response.model_id}"
        return draft
