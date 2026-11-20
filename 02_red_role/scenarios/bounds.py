"""Per-round bounds + safety enforcement (Epic C3).

The red_proposal JSON Schema already enforces *static* bounds (family/action
enums, 1-10 steps). This module enforces the *per-round* bounds that depend on
the specific red_input (this round may allow only a subset of families/actions
and a lower step ceiling), plus a safety deny-list that rejects anything that
reads like real attack activity rather than a benign look-alike.

`check_bounds` returns a list of human-readable violations. An empty list means
the proposal is in scope and safe to emit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class BoundsViolation:
    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


# Phrases that indicate genuinely malicious intent (not a benign look-alike).
# Matched case-insensitively against the proposal's free-text fields.
_UNSAFE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bransomware\b", "references ransomware"),
    (r"\bexfiltrat", "describes data exfiltration"),
    (r"\bc2\b|\bcommand[- ]and[- ]control\b", "references command-and-control"),
    (r"\breverse shell\b", "describes a reverse shell"),
    (r"\bcredential (theft|dump|harvest)", "describes credential theft"),
    (r"\bmimikatz\b", "references a credential-dumping tool"),
    (r"\bprivilege escalation\b", "describes privilege escalation"),
    (r"\blateral movement\b", "describes lateral movement"),
    (r"\bdisable (av|antivirus|edr|defender)\b", "describes disabling security tooling"),
    (r"\bencrypt .*files? for ransom", "describes ransom encryption"),
)


def _text_blob(proposal: dict) -> str:
    """Concatenate the free-text fields we scan for unsafe content."""
    sc = proposal.get("scenario", {})
    parts = [
        sc.get("title", ""),
        sc.get("description", ""),
        sc.get("expected_signal", ""),
        proposal.get("benign_justification", ""),
        proposal.get("rationale", ""),
    ]
    for step in sc.get("workflow_steps", []):
        parts.append(step.get("target", ""))
        parts.append(step.get("benign_context", ""))
    return " \n ".join(p for p in parts if p).lower()


def check_bounds(proposal: dict, red_input: dict) -> list[BoundsViolation]:
    """Validate a proposal against this round's constraints and the safety list."""
    violations: list[BoundsViolation] = []
    scenario = proposal.get("scenario", {})
    constraints = red_input.get("benign_constraints", {})

    allowed_families = set(constraints.get("allowed_scenario_families", []))
    allowed_actions = set(constraints.get("allowed_actions", []))
    max_steps = constraints.get("max_workflow_steps")

    # 1. Family must be allowed this round.
    family = scenario.get("family")
    if allowed_families and family not in allowed_families:
        violations.append(BoundsViolation(
            "family_out_of_scope",
            f"family '{family}' not in this round's allowed families {sorted(allowed_families)}",
        ))

    # 2. Every step action must be allowed this round.
    steps = scenario.get("workflow_steps", [])
    if allowed_actions:
        for i, step in enumerate(steps):
            action = step.get("action")
            if action not in allowed_actions:
                violations.append(BoundsViolation(
                    "action_out_of_scope",
                    f"step {i} action '{action}' not in allowed actions {sorted(allowed_actions)}",
                ))

    # 3. Step count must respect this round's ceiling.
    if isinstance(max_steps, int) and len(steps) > max_steps:
        violations.append(BoundsViolation(
            "too_many_steps",
            f"{len(steps)} steps exceeds this round's max of {max_steps}",
        ))

    # 4. Safety deny-list: reject real-attack content.
    blob = _text_blob(proposal)
    for pattern, reason in _UNSAFE_PATTERNS:
        if re.search(pattern, blob):
            violations.append(BoundsViolation("unsafe_content", reason))

    return violations
