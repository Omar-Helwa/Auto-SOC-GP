"""Record a human review of one prepared label set.

Prints a summary of the set (label, scenario, source, and one example per
group), then asks the reviewer to type a confirmation. Only after that are
labels stamped ``reviewed`` with the reviewer's name and time. Individual
events can be marked disputed or relabelled. A disputed label keeps
``coverage.complete=false``, so the set stays out of Judge evaluation.

    python review_labels.py --eval-set-id evalset-demo-lsass-v1 --reviewer "maro"
    python review_labels.py --eval-set-id evalset-demo-lsass-v1 --reviewer "maro" --sheet review.csv
    python review_labels.py ... --dispute evt-... --relabel evt-...=benign

``--sheet`` writes one row per event for a detailed review and changes nothing.
The previous label file is kept as reviewed_label_set.json.bak-<timestamp>.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from paths import CONTRACTS, prepared_dir

KEY_FIELDS = (
    "EventID", "SourceImage", "TargetImage", "StartModule", "StartFunction",
    "Image", "ParentImage", "CommandLine", "ScriptBlockText", "User", "Computer",
)


def _example(fields: dict) -> str:
    parts = []
    for name in KEY_FIELDS:
        value = fields.get(name)
        if value not in (None, ""):
            text = str(value).replace("\n", " ")
            parts.append(f"{name}={text[:120]}{'...' if len(text) > 120 else ''}")
    return "; ".join(parts) or "(no parsed fields)"


def load(set_dir: Path) -> tuple[dict, dict[str, dict]]:
    labels = json.loads((set_dir / "labels" / "reviewed_label_set.json").read_text(encoding="utf-8"))
    events = {}
    with (set_dir / "events" / "events.jsonl").open(encoding="utf-8") as source:
        for line in source:
            event = json.loads(line)
            events[event["event_id"]] = event
    return labels, events


def summary(labels: dict, events: dict[str, dict]) -> str:
    groups: dict[tuple, list[str]] = defaultdict(list)
    for label in labels["labels"]:
        groups[(label["label"], label.get("scenario_id", "-"), label["source"])].append(label["event_id"])
    lines = [
        f"Label set {labels['label_set_id']} ({labels['dataset']['evaluation_set_id']}, "
        f"dataset_version {labels['dataset']['dataset_version']})",
        f"Events: {len(labels['labels'])}; current review status: "
        f"{dict(Counter(item['review']['status'] for item in labels['labels']))}",
        "",
    ]
    for (label, scenario, source), ids in sorted(groups.items()):
        synthetic = "  [SYNTHETIC]" if "synthetic" in scenario else ""
        lines.append(f"{label:7} {len(ids):5}  {scenario}  ({source}){synthetic}")
        lines.append(f"        e.g. {ids[0]}: {_example(events.get(ids[0], {}).get('fields', {}))}")
    return "\n".join(lines)


def write_sheet(labels: dict, events: dict[str, dict], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["event_id", "label", "scenario_id", "source", *KEY_FIELDS])
        for label in labels["labels"]:
            fields = events.get(label["event_id"], {}).get("fields", {})
            writer.writerow([
                label["event_id"], label["label"], label.get("scenario_id", ""), label["source"],
                *(str(fields.get(name, "")) for name in KEY_FIELDS),
            ])


def apply_review(
    labels: dict,
    *,
    reviewer: str,
    disputed: set[str],
    relabel: dict[str, str],
    reviewed_at: str,
) -> dict:
    ids = {label["event_id"] for label in labels["labels"]}
    unknown = sorted((disputed | set(relabel)) - ids)
    if unknown:
        raise SystemExit(f"unknown event_id(s): {unknown}")
    for label in labels["labels"]:
        event_id = label["event_id"]
        if event_id in relabel:
            label["label"] = relabel[event_id]
            if relabel[event_id] == "benign":
                label.pop("attack_technique", None)
        if event_id in disputed:
            label["review"] = {"status": "disputed", "reviewer": reviewer, "reviewed_at": reviewed_at}
        else:
            label["review"] = {"status": "reviewed", "reviewer": reviewer, "reviewed_at": reviewed_at}
    labels["coverage"] = {
        "total_events": len(labels["labels"]),
        "complete": not disputed and len(labels["labels"]) > 0,
    }
    return labels


def _validate(labels: dict) -> None:
    import jsonschema

    schema = json.loads(
        (CONTRACTS / "telemetry_evidence" / "reviewed_label_set.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.validate(labels, schema)


def main(argv: list[str] | None = None, *, confirm: Callable[[str], str] | None = None,
         set_dir: Path | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--eval-set-id", required=True)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--sheet", type=Path, help="write a per-event CSV for review and exit")
    parser.add_argument("--dispute", action="append", default=[], metavar="EVENT_ID")
    parser.add_argument("--relabel", action="append", default=[], metavar="EVENT_ID=benign|attack")
    args = parser.parse_args(argv)
    if not args.reviewer.strip() or not args.reviewer.isprintable():
        raise SystemExit("--reviewer must be a printable name")

    set_dir = set_dir or prepared_dir(args.eval_set_id)
    labels, events = load(set_dir)
    if labels["dataset"]["evaluation_set_id"] != args.eval_set_id:
        raise SystemExit("label set does not belong to --eval-set-id")
    if args.sheet:
        write_sheet(labels, events, args.sheet)
        print(f"wrote {len(labels['labels'])} rows to {args.sheet}; no labels were changed")
        return 0

    relabel = {}
    for item in args.relabel:
        event_id, _, value = item.partition("=")
        if value not in ("benign", "attack"):
            raise SystemExit(f"--relabel needs EVENT_ID=benign or EVENT_ID=attack, got {item!r}")
        relabel[event_id] = value

    print(summary(labels, events))
    if relabel:
        print(f"\nRelabel: {relabel}")
    if args.dispute:
        print(f"Disputed: {sorted(set(args.dispute))}")
    phrase = f"REVIEWED {args.eval_set_id}"
    prompt = (
        f"\nBy confirming, {args.reviewer} states they reviewed these labels against the events.\n"
        f"Type {phrase!r} to record the review: "
    )
    if confirm is None:
        if not sys.stdin.isatty():
            print("Refusing: the review must be confirmed in an interactive terminal.")
            return 1
        confirm = input
    if confirm(prompt).strip() != phrase:
        print("Not confirmed; nothing was changed.")
        return 1

    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    updated = apply_review(labels, reviewer=args.reviewer.strip(), disputed=set(args.dispute),
                           relabel=relabel, reviewed_at=now)
    _validate(updated)
    label_path = set_dir / "labels" / "reviewed_label_set.json"
    backup = label_path.with_name(f"{label_path.name}.bak-{now.replace(':', '').replace('-', '')}")
    shutil.copy2(label_path, backup)
    label_path.write_text(json.dumps(updated, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest_path = set_dir / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["labels_reviewed"] = updated["coverage"]["complete"]
        manifest["reviewed_by"] = args.reviewer.strip()
        manifest["reviewed_at"] = now
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"recorded review by {args.reviewer}: complete={updated['coverage']['complete']} "
          f"(backup {backup.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
