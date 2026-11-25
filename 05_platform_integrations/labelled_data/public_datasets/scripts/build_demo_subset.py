"""Build a compact, unreviewed demo set for the imported LSASS rule.

The subset contains attack events matching the rule's initial search and all
benign events. It is intentionally not promoted to reviewed ground truth.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from paths import CONTRACTS, prepared_dir


SOURCE_EVAL_SET = "evalset-multi-v1"
DETECTION_ID = "67d4dbef-9564-4699-8da8-03a151529edc"
RULE_SOURCES = {
    "WinEventLog:Microsoft-Windows-Sysmon/Operational",
    "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
}


def _checksum(event_ids: set[str]) -> str:
    return hashlib.sha256("\n".join(sorted(event_ids)).encode("utf-8")).hexdigest()


def _matches_rule_head(event: dict[str, Any]) -> bool:
    fields = event.get("fields")
    if not isinstance(fields, dict):
        return False
    target_image = fields.get("TargetImage")
    return (
        event.get("source") in RULE_SOURCES
        and str(fields.get("EventID", "")) == "8"
        and isinstance(target_image, str)
        and target_image.casefold().endswith("\\lsass.exe")
    )


def build_demo_subset(
    source_eval_set: str = SOURCE_EVAL_SET,
    output_eval_set: str = "evalset-demo-lsass-v1",
) -> Path:
    source_dir = prepared_dir(source_eval_set)
    output_dir = prepared_dir(output_eval_set)
    if source_dir == output_dir:
        raise ValueError("the demo set must not overwrite its source evaluation set")
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite existing prepared set: {output_dir}")

    events_path = source_dir / "events" / "events.jsonl"
    selected_events: list[dict[str, Any]] = []
    with events_path.open(encoding="utf-8") as source:
        for line in source:
            event = json.loads(line)
            if event.get("index") == "autosoc_benign" or (
                event.get("index") == "autosoc_attack" and _matches_rule_head(event)
            ):
                selected_events.append(event)

    selected_ids = {event["event_id"] for event in selected_events}
    if len(selected_ids) != len(selected_events):
        raise ValueError("source evaluation set contains duplicate selected event IDs")
    if not any(event.get("index") == "autosoc_attack" for event in selected_events):
        raise ValueError("no attack events matched the selected rule's initial search")
    if not any(event.get("index") == "autosoc_benign" for event in selected_events):
        raise ValueError("the source evaluation set has no benign events")

    label_path = source_dir / "labels" / "reviewed_label_set.json"
    label_set = json.loads(label_path.read_text(encoding="utf-8"))
    labels = [
        label for label in label_set["labels"] if label["event_id"] in selected_ids
    ]
    label_ids = {label["event_id"] for label in labels}
    if label_ids != selected_ids:
        raise ValueError("selected events and source labels do not have identical coverage")
    label_set["label_set_id"] = f"labels-{output_eval_set}"
    label_set["dataset"]["evaluation_set_id"] = output_eval_set
    label_set["dataset"]["evaluation_set_checksum"] = _checksum(selected_ids)
    label_set["coverage"] = {
        "total_events": len(labels),
        "complete": bool(labels)
        and all(label["review"]["status"] == "reviewed" for label in labels),
    }
    label_set["labels"] = labels

    source_hec_path = source_dir / "events" / "splunk_hec.jsonl"
    selected_hec: list[str] = []
    with source_hec_path.open(encoding="utf-8") as source:
        for line in source:
            payload = json.loads(line)
            event_id = payload.get("fields", {}).get("event_id")
            if event_id in selected_ids:
                payload["fields"]["autosoc_eval_set"] = output_eval_set
                selected_hec.append(json.dumps(payload, ensure_ascii=False))
    if {
        json.loads(line)["fields"]["event_id"] for line in selected_hec
    } != selected_ids:
        raise ValueError("selected HEC events do not match the normalized event IDs")

    source_detection = source_dir / "detections" / f"{DETECTION_ID}.json"
    detection_index = json.loads(
        (source_dir / "detections" / "index.json").read_text(encoding="utf-8")
    )
    matching_index = [
        item for item in detection_index if item.get("detection_id") == DETECTION_ID
    ]
    if not source_detection.exists() or len(matching_index) != 1:
        raise ValueError("the selected imported detection is missing or ambiguous")

    output_dir.mkdir(parents=True)
    (output_dir / "events").mkdir()
    (output_dir / "labels").mkdir()
    (output_dir / "detections").mkdir()
    (output_dir / "events" / "events.jsonl").write_text(
        "".join(json.dumps(event, ensure_ascii=False) + "\n" for event in selected_events),
        encoding="utf-8",
    )
    (output_dir / "events" / "splunk_hec.jsonl").write_text(
        "".join(line + "\n" for line in selected_hec), encoding="utf-8"
    )
    (output_dir / "labels" / "reviewed_label_set.json").write_text(
        json.dumps(label_set, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (output_dir / "detections" / f"{DETECTION_ID}.json").write_text(
        source_detection.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (output_dir / "detections" / "index.json").write_text(
        json.dumps(matching_index, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    attack_count = sum(event["index"] == "autosoc_attack" for event in selected_events)
    benign_count = sum(event["index"] == "autosoc_benign" for event in selected_events)
    manifest = {
        "evaluation_set_id": output_eval_set,
        "source_evaluation_set_id": source_eval_set,
        "evaluation_set_checksum": label_set["dataset"]["evaluation_set_checksum"],
        "selection": {
            "detection_id": DETECTION_ID,
            "rule_version": "15",
            "attack_events": "initial search matches",
            "benign_events": "all available",
        },
        "counts": {"attack": attack_count, "benign": benign_count},
        "labels_reviewed": label_set["coverage"]["complete"],
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return output_dir


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-eval-set", default=SOURCE_EVAL_SET)
    parser.add_argument("--eval-set-id", default="evalset-demo-lsass-v1")
    args = parser.parse_args()
    output_dir = build_demo_subset(args.source_eval_set, args.eval_set_id)
    labels = json.loads(
        (output_dir / "labels" / "reviewed_label_set.json").read_text(encoding="utf-8")
    )
    schema = json.loads(
        (CONTRACTS / "telemetry_evidence" / "reviewed_label_set.schema.json").read_text(
            encoding="utf-8"
        )
    )
    import jsonschema

    jsonschema.validate(labels, schema)
    print(f"prepared={output_dir}")
    print(f"events={labels['coverage']['total_events']}")
    print(f"labels_reviewed={labels['coverage']['complete']}")
    print(f"checksum={labels['dataset']['evaluation_set_checksum']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
