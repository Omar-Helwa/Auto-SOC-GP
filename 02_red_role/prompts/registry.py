"""Versioned red prompt templates (Epic E3).

Maps a prompt version id to its system + task template files and renders them
against a RedContext. The version that was used is recorded in the proposal's
`prompt_version`, so a round is reproducible. Changing a prompt means adding a
new version here and new template files — existing versions are never edited in
place.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from role_context.builder import RedContext

_DIR = Path(__file__).resolve().parent


class UnknownPromptVersion(Exception):
    """Raised when an unregistered prompt version is requested."""


@dataclass(frozen=True)
class PromptTemplates:
    version: str
    system_file: str
    task_file: str


# Registered prompt versions. Key = the id used in red_input.prompt_version.
PROMPT_VERSIONS: dict[str, PromptTemplates] = {
    "red-system@0.1.0": PromptTemplates(
        version="red-system@0.1.0",
        system_file="red_system.v0_1_0.md",
        task_file="red_task.v0_1_0.md",
    ),
}

DEFAULT_PROMPT_VERSION = "red-system@0.1.0"


def _read(name: str) -> str:
    return (_DIR / name).read_text(encoding="utf-8")


def _render_task(template: str, ctx: RedContext) -> str:
    forbidden = "\n".join(f"- {n}" for n in ctx.forbidden_notes) or "- (none)"
    if ctx.permitted_evidence_refs:
        evidence = "\n".join(
            f"- {e.get('evidence_id')} ({e.get('evidence_type')})"
            for e in ctx.permitted_evidence_refs
        )
    else:
        evidence = "- (none)"
    replacements = {
        "<<DETECTION_ID>>": ctx.detection_id,
        "<<RULE_VERSION>>": ctx.rule_version,
        "<<DETECTION_SUMMARY>>": ctx.detection_summary,
        "<<FAMILIES_BLOCK>>": ctx.families_block,
        "<<ALLOWED_ACTIONS>>": ", ".join(ctx.allowed_actions),
        "<<MAX_STEPS>>": str(ctx.max_workflow_steps),
        "<<FORBIDDEN_NOTES>>": forbidden,
        "<<EVIDENCE_BLOCK>>": evidence,
    }
    out = template
    for token, value in replacements.items():
        out = out.replace(token, value)
    return out


def render(prompt_version: str, ctx: RedContext) -> dict[str, str]:
    """Return {'system': ..., 'task': ..., 'version': ...} for a prompt version."""
    templates = PROMPT_VERSIONS.get(prompt_version)
    if templates is None:
        raise UnknownPromptVersion(
            f"Unknown prompt version {prompt_version!r}; known: {sorted(PROMPT_VERSIONS)}"
        )
    system = _read(templates.system_file)
    task = _render_task(_read(templates.task_file), ctx)
    return {"system": system, "task": task, "version": templates.version}
