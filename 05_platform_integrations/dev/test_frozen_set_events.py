"""Frozen-set identity and fields derived from Splunk's raw event text."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

from splunk_execution import TelemetryEvidence
from validation.events import fields_from_raw, normalize_frozen_set_event, stable_event_id

SCRIPTS = Path(__file__).resolve().parents[1] / "labelled_data" / "public_datasets" / "scripts"
XML = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Microsoft-Windows-Sysmon'/><EventID>8</EventID>"
    "<TimeCreated SystemTime='2026-11-20T08:15:02.104Z'/><Execution ProcessID='2152' ThreadID='1'/>"
    "<Computer>lab-ws-01</Computer><Security UserID='S-1-5-18'/></System><EventData>"
    "<Data Name='SourceImage'>C:\\Program Files\\Contoso EDR\\ContosoAgent.exe</Data>"
    "<Data Name='TargetImage'>C:\\Windows\\System32\\lsass.exe</Data><Data Name='StartModule'>-</Data>"
    "</EventData></Event>"
)


def splunk_event(raw: str | None, event_id: str = "5:15788", **fields: str) -> TelemetryEvidence:
    return TelemetryEvidence(
        event_id=event_id, timestamp="2026-11-20T08:15:02.104+00:00",
        fields={"index": "autosoc_lab", "autosoc_eval_set": "evalset-x", **fields}, raw=raw,
    )


class FrozenSetEventTests(unittest.TestCase):
    def test_identity_matches_the_dataset_builder(self) -> None:
        spec = importlib.util.spec_from_file_location("builder_under_test", SCRIPTS / "build_evaluation_set.py")
        sys.path.insert(0, str(SCRIPTS))
        try:
            builder = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(builder)
        finally:
            sys.path.remove(str(SCRIPTS))
        self.assertEqual(stable_event_id(XML), "evt-" + builder._sha256(XML.encode("utf-8"))[:32])
        expected = {k: v for k, v in builder.parse_xml_event(XML).items() if k != "_time"}
        self.assertEqual(fields_from_raw(XML), expected)

    def test_splunk_locator_is_replaced_and_raw_fields_fill_gaps(self) -> None:
        event = normalize_frozen_set_event(splunk_event(XML))
        self.assertEqual(event.event_id, stable_event_id(XML))
        self.assertEqual(event.fields["EventID"], "8")
        self.assertEqual(event.fields["TargetImage"], "C:\\Windows\\System32\\lsass.exe")
        self.assertEqual(event.fields["UserID"], "S-1-5-18")
        self.assertEqual(event.fields["autosoc_eval_set"], "evalset-x")
        self.assertEqual(event.raw, XML)

    def test_fields_splunk_returned_take_precedence(self) -> None:
        event = normalize_frozen_set_event(splunk_event(XML, Computer="from-splunk"))
        self.assertEqual(event.fields["Computer"], "from-splunk")

    def test_indexed_id_that_disagrees_with_the_raw_text_is_rejected(self) -> None:
        tampered = splunk_event(XML.replace("ContosoAgent", "Other"), event_id=stable_event_id(XML))
        with self.assertRaisesRegex(ValueError, "hashes to"):
            normalize_frozen_set_event(tampered)
        self.assertEqual(
            normalize_frozen_set_event(splunk_event(XML, event_id=stable_event_id(XML))).event_id,
            stable_event_id(XML),
        )

    def test_events_without_raw_text_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "no raw text"):
            normalize_frozen_set_event(splunk_event(None))

    def test_json_and_unparsed_raw(self) -> None:
        raw = json.dumps({"CommandLine": "notepad.exe", "EventID": 1, "nested": {"x": 1}, "ok": True})
        self.assertEqual(fields_from_raw(raw), {"CommandLine": "notepad.exe", "EventID": "1", "ok": "true"})
        self.assertEqual(fields_from_raw("plain text"), {})
        self.assertEqual(fields_from_raw("<Event broken"), {})


if __name__ == "__main__":
    unittest.main()
