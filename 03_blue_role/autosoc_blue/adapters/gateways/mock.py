"""Mock model gateway: deterministic answers, no network, no key.

It "reads" the prompt the way a model would (the yaml rule and the JSON data
block), and answers with a JSON proposal built by the deterministic logic. Modes:

  normal         a good proposal
  bad_then_good  first call: an evasive CommandLine-only exclusion, then good ones
                 (shows the pre-flight retry)
  always_bad     always the evasive proposal (shows the deterministic fallback)
  malformed      text that is not JSON
  refusal        a refusal sentence
  timeout        raises ModelTimeout
  unavailable    raises ModelUnavailable

``custom_text`` overrides the answer text (any mode except timeout/unavailable).
"""

from __future__ import annotations

import json
import re

from ...core.context import BlueContext
from ...ports import ModelResponse, ModelTimeout, ModelUnavailable
from ...rule_edits.apply import parse_rule
from ...schemas.models import BlueInput
from ..deterministic import DeterministicProposer

MODES = ("normal", "bad_then_good", "always_bad", "malformed", "refusal", "timeout", "unavailable")

_YAML = re.compile(r"```(?:yaml|spl)\n(.*?)\n```", re.DOTALL)
_DATA = re.compile(r"<blue_input>\n(.*?)\n</blue_input>", re.DOTALL)


def _read_prompt(task: str) -> BlueContext:
    yaml_match, data_match = _YAML.search(task), _DATA.search(task)
    if not yaml_match or not data_match:
        raise ValueError("mock gateway: the task has no rule block or <blue_input> block")
    data = json.loads(data_match.group(1))
    rule_text = yaml_match.group(1) + "\n"

    def case(c):
        return {"evidence_reference": {"evidence_id": c["evidence_id"], "evidence_type": "reviewed_label"},
                "observed_fields": c["observed_fields"], **({"label_note": c["label_note"]} if "label_note" in c else {})}

    det = data["detection"]
    raw = {
        "contract_version": "0.1.0", "task_id": data["task_id"], "prompt_version": "blue-system@0.1.0",
        "output_contract_version": "0.1.0",
        "detection": {**det, "rule_text": rule_text},
        "false_positives": [case(c) for c in data["false_positives"]],
        "must_detect": [case(c) for c in data["must_detect"]],
        "edit_constraints": data["edit_constraints"],
    }
    inp = BlueInput.from_dict(raw)
    from ...core.context import build_context

    return build_context(inp)


def _draft_to_json(draft) -> str:
    return json.dumps({
        "edits": [e.to_dict() for e in draft.edits],
        "addressed_false_positives": draft.addressed_false_positives,
        "justification": draft.justification,
        "expected_effect": "Removes the listed false positives; the must-detect events should still match.",
        "rationale": draft.rationale or "",
    })


def _bad_json(ctx: BlueContext) -> str:
    """An exclusion on an attacker-controllable field only: the classic evasion recipe."""
    fp = ctx.false_positives[0]
    attacker = ctx.constraints.attacker_controllable_fields
    field = next((f for f in attacker if f in fp.observed_fields), None) or next(iter(fp.observed_fields))
    value = fp.observed_fields[field][:60]
    return json.dumps({
        "edits": [{"operation": "add_exclusion",
                   "conditions": [{"field": field, "modifier": "contains", "values": [value]}],
                   "reason": "Exclude the command line seen in the false positive."}],
        "addressed_false_positives": [fp.evidence_id],
        "justification": "The command line is unique to the false positive.",
    })


class MockModelGateway:
    def __init__(self, mode: str = "normal", custom_text: str | None = None):
        if mode not in MODES:
            raise ValueError(f"unknown mock mode {mode!r}; choose from {MODES}")
        self.mode, self.custom_text = mode, custom_text
        self.calls: list[dict] = []

    def generate(self, system: str, task: str, params: dict | None = None) -> ModelResponse:
        self.calls.append({"system": system, "task": task, "params": params})
        if self.mode == "timeout":
            raise ModelTimeout("mock timeout")
        if self.mode == "unavailable":
            raise ModelUnavailable("mock gateway unavailable")
        if self.custom_text is not None:
            return ModelResponse(self.custom_text, "mock")
        if self.mode == "malformed":
            return ModelResponse("Sure! Here is the edit you asked for: exclude the scheduler.", "mock")
        if self.mode == "refusal":
            return ModelResponse("I can't help with that request.", "mock")
        ctx = _read_prompt(task)
        if self.mode == "always_bad" or (self.mode == "bad_then_good" and len(self.calls) == 1):
            return ModelResponse(_bad_json(ctx), "mock")
        draft = DeterministicProposer().propose(ctx)
        return ModelResponse(_draft_to_json(draft), "mock")
