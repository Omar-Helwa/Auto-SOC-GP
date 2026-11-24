"""Load and render the versioned Blue prompts.

Templates use ``{{name}}`` placeholders. The version string is the one the
orchestrator puts in ``blue_input.prompt_version``. An unknown version falls
back to the latest template (the label is still echoed in the proposal).
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.context import BlueContext

PROMPTS_DIR = Path(__file__).resolve().parent
LATEST = "blue-system@0.1.0"
_FILES = {
    "blue-system@0.1.0": ("blue_system.v0_1_0.md", "blue_task.v0_1_0.md"),
}
MAX_FIELD_CHARS = 1200  # long values are shortened ONLY inside the prompt

INPUT_OPEN, INPUT_CLOSE = "<blue_input>", "</blue_input>"


def _fill(template: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        template = template.replace("{{" + key + "}}", value)
    return template


def _short(value: str) -> str:
    return value if len(value) <= MAX_FIELD_CHARS else value[:MAX_FIELD_CHARS] + "...[truncated]"


def _case(case) -> dict:
    return {
        "evidence_id": case.evidence_id,
        "observed_fields": {k: _short(v) for k, v in case.observed_fields.items()},
        **({"label_note": case.label_note} if case.label_note else {}),
    }


def render(version: str, ctx: BlueContext, feedback: list[str] | None = None) -> dict:
    sys_file, task_file = _FILES.get(version, _FILES[LATEST])
    resolved = version if version in _FILES else LATEST
    system = (PROMPTS_DIR / sys_file).read_text(encoding="utf-8")
    template = (PROMPTS_DIR / task_file).read_text(encoding="utf-8")

    inp, c = ctx.input, ctx.constraints
    prior = "\n".join(
        f"- [{p.decision}] {p.summary}" + (f" (reason: {p.failure_reason})" if p.failure_reason else "")
        for p in inp.prior_blue_edits
    ) or "- none"
    feedback_block = ""
    if feedback:
        feedback_block = (
            "\nYour previous answer was REJECTED by the automatic pre-flight check. Fix these problems "
            "and answer again:\n" + "\n".join(f"- {f}" for f in feedback) + "\n"
        )
    data = {
        "task_id": inp.task_id,
        "detection": {
            "detection_id": inp.detection.detection_id,
            "rule_version": inp.detection.rule_version,
            "rule_format": inp.detection.rule_format,
            "logic_summary": inp.detection.logic_summary,
            "attack_techniques": inp.detection.attack_techniques,
        },
        "edit_constraints": {
            "allowed_operations": c.allowed_operations,
            "allowed_fields": c.allowed_fields,
            "attacker_controllable_fields": c.attacker_controllable_fields,
            "max_edits": c.max_edits,
        },
        "false_positives": [_case(x) for x in inp.false_positives],
        "must_detect": [_case(x) for x in inp.must_detect],
    }
    task = _fill(template, {
        "detection_id": inp.detection.detection_id,
        "rule_version": inp.detection.rule_version,
        "logic_summary": inp.detection.logic_summary,
        "rule_text": inp.detection.rule_text.rstrip(),
        "selections": ", ".join(ctx.selection_names),
        "allowed_operations": ", ".join(c.allowed_operations),
        "allowed_fields": ", ".join(c.allowed_fields),
        "attacker_fields": ", ".join(c.attacker_controllable_fields) or "(none listed)",
        "max_edits": str(c.max_edits),
        "prior_edits": prior,
        "feedback_block": feedback_block,
        "input_json": json.dumps(data, indent=2, ensure_ascii=False),
    })
    return {"system": system, "task": task, "version": resolved}
