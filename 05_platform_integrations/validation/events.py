"""Frozen-set event identity and fields, derived from the raw text Splunk returns.

The dataset builders (labelled_data/public_datasets/scripts/build_evaluation_set.py)
give every event ``event_id = "evt-" + sha256(raw)[:32]`` and index that ID as
an HEC field. Splunk's search export does not reliably return indexed or
search-time fields, but it does return ``_raw``. Recomputing the ID from the
raw text gives the same identity the labels use, without trusting Splunk's
internal locator (``_cd``), and a changed raw event no longer matches its label.

Fields that Splunk did not return are parsed from the raw text the same way
the builder parses Windows XML and JSON events.
"""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import replace
from typing import Any

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_SYSTEM_ATTRIBUTES = {"Provider": "Name", "Execution": "ProcessID", "Security": "UserID"}
_ATTRIBUTE_FIELD = {"Provider": "Provider", "Execution": "ExecProcessID", "Security": "UserID"}
_STABLE_ID = re.compile(r"^evt-[0-9a-f]{32}$")


def stable_event_id(raw: str) -> str:
    return "evt-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def fields_from_raw(raw: str) -> dict[str, str]:
    """Parse a one-line Windows XML event or JSON object into string fields."""
    text = raw.strip()
    if text.startswith("<Event"):
        return _xml_fields(text)
    if text.startswith("{"):
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            return {}
        if not isinstance(value, dict):
            return {}
        fields = {}
        for name, item in value.items():
            if isinstance(item, bool):
                fields[name] = "true" if item else "false"
            elif isinstance(item, (str, int, float)):
                fields[name] = str(item)
        return fields
    return {}


def _xml_fields(text: str) -> dict[str, str]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return {}
    fields: dict[str, str] = {}
    system = root.find(f"{_NS}System")
    if system is not None:
        for child in system:
            tag = child.tag.replace(_NS, "")
            if tag in _SYSTEM_ATTRIBUTES:
                fields[_ATTRIBUTE_FIELD[tag]] = child.get(_SYSTEM_ATTRIBUTES[tag], "")
            elif tag != "TimeCreated" and child.text and child.text.strip():
                fields[tag] = child.text.strip()
    for section in ("EventData", "UserData"):
        node = root.find(f"{_NS}{section}")
        if node is None:
            continue
        for item in node.iter():
            name = item.get("Name") or item.tag.replace(_NS, "")
            if item is not node and item.text and item.text.strip():
                fields[name] = item.text.strip()
    return fields


def normalize_frozen_set_event(event: Any) -> Any:
    """Give a Splunk ``TelemetryEvidence`` its frozen-set identity and raw fields.

    Raises ``ValueError`` when the event has no raw text, or when Splunk
    returned a frozen-set ``event_id`` that the raw text does not hash to.
    Fields Splunk returned are kept; parsed fields only fill gaps.
    """
    raw = getattr(event, "raw", None)
    if not isinstance(raw, str) or not raw:
        raise ValueError(
            f"Splunk event {event.event_id!r} has no raw text; its frozen-set identity cannot be derived"
        )
    derived = stable_event_id(raw)
    if _STABLE_ID.fullmatch(event.event_id) and event.event_id != derived:
        raise ValueError(
            f"Splunk returned event_id {event.event_id!r} but the raw event hashes to {derived!r}"
        )
    fields = {**fields_from_raw(raw), **dict(event.fields)}
    return replace(event, event_id=derived, fields=fields)
