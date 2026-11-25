"""Compile bounded blue-proposal edits against a trusted base search."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4

from .proposals import require_valid_contract


_SELECTION_PLACEHOLDER = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}")
_SELECTION_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_FIELD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_PRESERVED_PIPELINE_RULE = (
    "67d4dbef-9564-4699-8da8-03a151529edc",
    "15",
)
_PRESERVED_PIPELINE_COMMANDS = {"stats", "convert", "search"}


def _split_spl_pipeline(spl: str) -> tuple[str, list[str]]:
    segments: list[str] = []
    current: list[str] = []
    in_quote = False
    index = 0
    while index < len(spl):
        char = spl[index]
        if in_quote and char == "\\" and index + 1 < len(spl):
            current.extend((char, spl[index + 1]))
            index += 2
            continue
        if char == '"':
            in_quote = not in_quote
            current.append(char)
        elif char == "|" and not in_quote:
            segments.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    if in_quote:
        raise ValueError("base SPL contains an unterminated quoted value")
    segments.append("".join(current))
    head = segments[0].strip()
    pipeline = [segment.strip() for segment in segments[1:]]
    if not head or any(not segment for segment in pipeline):
        raise ValueError("base SPL contains an empty search or pipeline segment")
    return head, pipeline


def _normalize_spl_whitespace(spl: str) -> str:
    output: list[str] = []
    in_quote = False
    escaped = False
    pending_space = False
    for char in spl:
        if in_quote:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_quote = False
        elif char == '"':
            if pending_space and output:
                output.append(" ")
            pending_space = False
            in_quote = True
            output.append(char)
        elif char.isspace():
            pending_space = bool(output)
        else:
            if pending_space and output:
                output.append(" ")
            pending_space = False
            output.append(char)
    return "".join(output).strip()


def _validate_preserved_pipeline(
    detection_id: str, rule_version: str, pipeline: list[str]
) -> None:
    if not pipeline:
        return
    if (detection_id, rule_version) != _PRESERVED_PIPELINE_RULE:
        raise ValueError(
            "preserved SPL pipelines are only supported for the approved imported rule"
        )
    for segment in pipeline:
        command = segment.split(None, 1)[0].lower()
        if command not in _PRESERVED_PIPELINE_COMMANDS:
            raise ValueError(f"pipeline command {command!r} is not approved")


@dataclass(frozen=True)
class BaseRule:
    """Trusted, read-only base SPL with optional named selection fragments.

    ``spl_template`` may reference a selection as ``{{selection_name}}``.
    Model-proposed edits can only change those fragments or add a filter. One
    imported rule may retain its approved, read-only stats/convert/search tail.
    """

    task_id: str
    detection_id: str
    rule_version: str
    spl_template: str
    selections: Mapping[str, str]

    def __post_init__(self) -> None:
        for name in ("task_id", "detection_id", "rule_version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.spl_template, str) or not self.spl_template.strip():
            raise ValueError("spl_template must be a non-empty string")
        if len(self.spl_template) > 20_000:
            raise ValueError("spl_template exceeds the 20000 character limit")
        if any(char in self.spl_template for char in (";", "`", "[", "]")):
            raise ValueError("base SPL contains an unsupported construct")
        if any(ord(char) < 32 and not char.isspace() for char in self.spl_template):
            raise ValueError("base SPL contains a control character")
        _, pipeline = _split_spl_pipeline(self.spl_template)
        _validate_preserved_pipeline(
            self.detection_id, self.rule_version, pipeline
        )
        if not isinstance(self.selections, Mapping):
            raise ValueError("selections must be a mapping")
        for name, expression in self.selections.items():
            if not isinstance(name, str) or not _SELECTION_NAME.fullmatch(name):
                raise ValueError(f"invalid selection name: {name!r}")
            if not isinstance(expression, str) or not expression.strip():
                raise ValueError(f"selection {name!r} must have a non-empty expression")
            if any(char in expression for char in ("|", ";", "`", "\n", "\r")):
                raise ValueError(f"selection {name!r} must be a read-only search expression")
        unknown = set(_SELECTION_PLACEHOLDER.findall(self.spl_template)) - set(
            self.selections
        )
        if unknown:
            raise ValueError(f"SPL template references unknown selections: {sorted(unknown)}")


def compile_candidate_rule(
    proposal: Mapping[str, Any],
    base_rule: BaseRule,
    *,
    candidate_rule_version: str,
) -> dict[str, Any]:
    """Validate and compile a blue proposal into the shared candidate_rule shape."""
    require_valid_contract(proposal, "blue_proposal")
    if proposal["task_id"] != base_rule.task_id:
        raise ValueError("blue proposal task_id does not match the base rule")
    detection = proposal["detection_under_test"]
    if detection["detection_id"] != base_rule.detection_id:
        raise ValueError("blue proposal detection_id does not match the base rule")
    if detection["rule_version"] != base_rule.rule_version:
        raise ValueError("blue proposal base rule_version does not match the base rule")
    if not isinstance(candidate_rule_version, str) or not candidate_rule_version.strip():
        raise ValueError("candidate_rule_version must be a non-empty string")

    selections = dict(base_rule.selections)
    exclusions: list[str] = []
    for edit in proposal["edits"]:
        predicate = _conditions_to_spl(edit["conditions"])
        if edit["operation"] == "add_exclusion":
            exclusions.append(predicate)
            continue

        selection_name = edit["target_selection"]
        if selection_name not in selections:
            raise ValueError(
                f"narrow_selection target {selection_name!r} is not present in the base rule"
            )
        if selection_name not in _SELECTION_PLACEHOLDER.findall(base_rule.spl_template):
            raise ValueError(
                f"narrow_selection target {selection_name!r} is not used by the base rule"
            )
        selections[selection_name] = f"({selections[selection_name]}) ({predicate})"

    compiled = _SELECTION_PLACEHOLDER.sub(
        lambda match: selections[match.group(1)], base_rule.spl_template
    ).strip()
    if exclusions:
        head, pipeline = _split_spl_pipeline(compiled)
        body = re.sub(r"^\s*search\s+", "", head, count=1, flags=re.IGNORECASE)
        if pipeline:
            if not body.strip():
                raise ValueError("base SPL search head has no detection conditions")
            compiled = f"search ({body}) NOT ({') NOT ('.join(exclusions)})"
            compiled += "".join(f" | {segment}" for segment in pipeline)
        elif body != head:
            # Keep an explicit leading ``search`` command outside the group:
            # "(search ...)" is not valid SPL.
            if not body.strip():
                raise ValueError("base SPL search head has no detection conditions")
            compiled = f"search ({body}) NOT ({') NOT ('.join(exclusions)})"
        else:
            compiled = f"({compiled}) NOT ({') NOT ('.join(exclusions)})"
    compiled = _normalize_spl_whitespace(compiled)
    if len(compiled) > 20_000:
        raise ValueError("compiled SPL exceeds the 20000 character limit")

    candidate = {
        "contract_version": "0.1.0",
        "candidate_id": str(uuid4()),
        "task_id": proposal["task_id"],
        "proposal_id": proposal["proposal_id"],
        "detection_id": base_rule.detection_id,
        "base_rule_version": base_rule.rule_version,
        "candidate_rule_version": candidate_rule_version,
        "applied_edit_count": len(proposal["edits"]),
        "compiled_rule": {
            "language": "splunk_spl",
            "text": compiled,
            "sha256": hashlib.sha256(compiled.encode("utf-8")).hexdigest(),
        },
        "validation": {
            "status": "passed",
            "checks": ["schema", "scope", "compile"],
            "validated_at": _utc_now(),
        },
    }
    require_valid_contract(candidate, "candidate_rule")
    return candidate


def render_base_rule(base_rule: BaseRule) -> str:
    """Return the exact SPL the compiler produces for ``base_rule`` with no edits.

    The baseline execution uses this text so baseline and candidate searches
    share one rendering (selection substitution and whitespace normalization).
    """
    rendered = _SELECTION_PLACEHOLDER.sub(
        lambda match: base_rule.selections[match.group(1)], base_rule.spl_template
    ).strip()
    rendered = _normalize_spl_whitespace(rendered)
    if len(rendered) > 20_000:
        raise ValueError("rendered SPL exceeds the 20000 character limit")
    return rendered


_STATS_BY = re.compile(r"\sby\s", re.IGNORECASE)
_BY_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


def event_level_search(rule_text: str) -> str:
    """Project a detection onto the events it alerts on, for event-identity matching.

    Splunk ``stats`` output has no per-event identity, so it cannot be joined
    to reviewed labels. This returns the rule's search head plus one
    ``field=*`` presence filter per ``stats ... by`` field: an event
    contributes to a ``stats by`` row only when every by-field is present.
    ``convert`` and a final ``search *`` do not filter and are dropped. Any
    other tail command (for example a ``search`` over aggregated values)
    would change which events alert, so it is rejected rather than ignored.
    """
    if not isinstance(rule_text, str) or not rule_text.strip():
        raise ValueError("rule_text must be a non-empty string")
    head, pipeline = _split_spl_pipeline(rule_text)
    body = re.sub(r"^\s*search\s+", "", head, count=1, flags=re.IGNORECASE).strip()
    if not body:
        raise ValueError("rule search head has no detection conditions")
    presence: list[str] = []
    seen_stats = False
    for position, segment in enumerate(pipeline):
        words = segment.split(None, 1)
        command = words[0].lower()
        if command == "convert":
            continue
        if command == "search" and len(words) == 2 and words[1].strip() == "*":
            if position != len(pipeline) - 1:
                raise ValueError("'search *' is only accepted as the final pipeline command")
            continue
        if command == "stats" and not seen_stats:
            seen_stats = True
            parts = _STATS_BY.split(segment)
            if len(parts) > 1:
                for field in re.split(r"[\s,]+", parts[-1].strip()):
                    if not field:
                        continue
                    if not _BY_FIELD.fullmatch(field):
                        raise ValueError(f"unsupported stats by-field: {field!r}")
                    if field not in presence:
                        presence.append(field)
            continue
        raise ValueError(
            f"pipeline command {command!r} may filter aggregated results; "
            "an event-level match set cannot be derived from this rule"
        )
    projected = f"({body})"
    if presence:
        projected += " " + " ".join(f"{field}=*" for field in presence)
    return _normalize_spl_whitespace(projected)


def _conditions_to_spl(conditions: list[Mapping[str, Any]]) -> str:
    terms: list[str] = []
    for condition in conditions:
        field = condition["field"]
        if not _FIELD_NAME.fullmatch(field):
            raise ValueError(f"invalid condition field: {field!r}")
        values = [
            _value_to_spl(field, condition["modifier"], value)
            for value in condition["values"]
        ]
        terms.append(values[0] if len(values) == 1 else f"({' OR '.join(values)})")
    return " ".join(terms)


def _value_to_spl(field: str, modifier: str, value: str) -> str:
    if any(ord(char) < 32 or char == "`" for char in value):
        raise ValueError("condition values cannot contain control characters or backticks")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    wildcard = {
        "equals": escaped,
        "contains": f"*{escaped}*",
        "startswith": f"{escaped}*",
        "endswith": f"*{escaped}",
    }[modifier]
    return f'{field}="{wildcard}"'


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
