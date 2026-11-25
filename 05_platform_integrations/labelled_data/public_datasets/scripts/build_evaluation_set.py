"""Convert downloaded logs into AutoSOC formats.

Inputs
  original/attacks/splunk_attack_data/<scenario>/  (from download_attack_data.py)  -> label "attack"
  original/attacks/benign/<anything>/*.log|*.xml|*.jsonl  (your lab / SOCBED) -> label "benign"
     Optional original/attacks/benign/<folder>/manifest.yml with sourcetype/source keys.

Outputs (in prepared/<evaluation_set_id>/)
  events.jsonl           normalized events, one per line, with stable event_id
  splunk_hec.jsonl       Splunk HEC /services/collector/event payloads (attack -> autosoc_attack,
                         benign -> autosoc_benign); event_id is an indexed field
  reviewed_label_set.json  matches 00_shared_contracts/telemetry_evidence/reviewed_label_set.schema.json
  manifest.json          what went in, counts, checksum

Labels are file-level: every event in an attack file is "attack". They are written as
"unreviewed" unless you pass --reviewer after spot-checking them.

Usage:
    python build_evaluation_set.py --eval-set-id evalset-ps-v1
    python build_evaluation_set.py --eval-set-id evalset-ps-v1 --reviewer "Ahmed Fahmy"
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import yaml

from paths import ATTACKS, BENIGN, ROOT as HERE, prepared_dir

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def parse_xml_event(line: str) -> dict:
    """Flatten one Windows XML event into a dict of fields."""
    root = ET.fromstring(line)
    fields: dict[str, str] = {}
    system = root.find(f"{NS}System")
    if system is not None:
        for child in system:
            tag = child.tag.replace(NS, "")
            if tag == "TimeCreated":
                fields["_time"] = child.get("SystemTime", "")
            elif tag == "Provider":
                fields["Provider"] = child.get("Name", "")
            elif tag == "Execution":
                fields["ExecProcessID"] = child.get("ProcessID", "")
            elif tag == "Security":
                fields["UserID"] = child.get("UserID", "")
            elif child.text and child.text.strip():
                fields[tag] = child.text.strip()
    for section in ("EventData", "UserData"):
        node = root.find(f"{NS}{section}")
        if node is None:
            continue
        for d in node.iter():
            name = d.get("Name") or d.tag.replace(NS, "")
            if d is not node and d.text and d.text.strip():
                fields[name] = d.text.strip()
    return fields


def iter_records(path: Path) -> Iterator[tuple[str, dict]]:
    """Yield (raw_text, fields). Supports one-XML-event-per-line and JSON lines."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if line.startswith("<Event"):
                try:
                    yield line, parse_xml_event(line)
                except ET.ParseError:
                    yield line, {}
            elif line.startswith("{"):
                try:
                    yield line, json.loads(line)
                except json.JSONDecodeError:
                    yield line, {}
            else:
                yield line, {}


def collect_sources() -> list[dict]:
    """Return one entry per log file with label + Splunk metadata."""
    sources: list[dict] = []
    for label, base in (("attack", ATTACKS), ("benign", BENIGN)):
        if not base.exists():
            continue
        for scen in sorted(p for p in base.iterdir() if p.is_dir()):
            man = {}
            if (scen / "manifest.yml").exists():
                man = yaml.safe_load((scen / "manifest.yml").read_text(encoding="utf-8")) or {}
            techniques = [t for t in man.get("mitre_technique", []) if TECH_RE.match(str(t))]
            by_name = {Path(d["path"]).name: d for d in man.get("datasets", []) if "path" in d}
            for f in sorted(scen.iterdir()):
                if f.name == "manifest.yml" or f.suffix not in (".log", ".xml", ".json", ".jsonl"):
                    continue
                meta = by_name.get(f.name, {})
                sources.append({
                    "label": label,
                    "scenario_id": scen.name,
                    "file": f,
                    "technique": techniques[0] if techniques and label == "attack" else None,
                    "sourcetype": meta.get("sourcetype", man.get("sourcetype", "XmlWinEventLog")),
                    "source": meta.get("source", man.get("source", f.name)),
                })
    return sources


def _epoch(ts: str) -> float | None:
    if not ts:
        return None
    try:
        ts = re.sub(r"(\.\d{6})\d+", r"\1", ts).replace("Z", "+00:00")
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return None


def build(eval_set_id: str, reviewer: str | None, dataset_version: str) -> Path:
    sources = collect_sources()
    if not sources:
        raise SystemExit("No input files. Run download_attack_data.py and/or add files under original/attacks/benign/.")
    if not any(s["label"] == "benign" for s in sources):
        print("WARNING: no benign data in original/attacks/benign/ - the judge cannot measure false-positive removal.")

    out = prepared_dir(eval_set_id)
    for sub in ("events", "labels"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    labels: list[dict] = []
    counts: dict[str, int] = {"attack": 0, "benign": 0, "duplicates_skipped": 0}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    review = {"status": "reviewed", "reviewer": reviewer, "reviewed_at": now} if reviewer else {"status": "unreviewed"}
    files_meta = []

    with (out / "events" / "events.jsonl").open("w", encoding="utf-8", newline="\n") as ev_fh, \
         (out / "events" / "splunk_hec.jsonl").open("w", encoding="utf-8", newline="\n") as hec_fh:
        for src in sources:
            try:
                file_sha = _sha256(src["file"].read_bytes())
            except OSError as exc:
                # Usually antivirus blocking a file with real malicious content.
                print(f"WARNING: skipped unreadable {src['file'].name} ({exc.strerror}); "
                      "add an antivirus exclusion for original/ if you need it")
                counts.setdefault("files_skipped", 0)
                counts["files_skipped"] += 1
                continue
            files_meta.append({"path": str(src["file"].relative_to(HERE)), "sha256": file_sha,
                               "label": src["label"], "scenario_id": src["scenario_id"]})
            for raw, fields in iter_records(src["file"]):
                event_id = "evt-" + _sha256(raw.encode("utf-8"))[:32]
                if event_id in seen:
                    counts["duplicates_skipped"] += 1
                    continue
                seen.add(event_id)
                index = "autosoc_attack" if src["label"] == "attack" else "autosoc_benign"
                ev_fh.write(json.dumps({
                    "event_id": event_id, "index": index, "sourcetype": src["sourcetype"],
                    "source": src["source"], "host": fields.get("Computer", "unknown"),
                    "_time": fields.get("_time"), "fields": fields, "raw": raw,
                }, ensure_ascii=False) + "\n")
                hec = {"event": raw, "index": index, "sourcetype": src["sourcetype"],
                       "source": src["source"], "host": fields.get("Computer", "unknown"),
                       "fields": {"event_id": event_id, "autosoc_eval_set": eval_set_id}}
                t = _epoch(fields.get("_time", ""))
                if t is not None:
                    hec["time"] = t
                hec_fh.write(json.dumps(hec, ensure_ascii=False) + "\n")

                lab = {"event_id": event_id, "label": src["label"],
                       # Both attack and SOCBED benign sets are public. Use lab_telemetry
                       # only for benign folders you recorded yourself (name starts "lab__").
                       "source": ("lab_telemetry" if src["scenario_id"].startswith("lab__")
                                  else "public_dataset"),
                       "scenario_id": src["scenario_id"], "review": dict(review),
                       "provenance_ref": f"{src['file'].name}@sha256:{file_sha}"}
                if src["technique"]:
                    lab["attack_technique"] = src["technique"]
                labels.append(lab)
                counts[src["label"]] += 1

    checksum = _sha256("\n".join(sorted(seen)).encode("utf-8"))
    label_set = {
        "contract_version": "0.1.0",
        "label_set_id": f"labels-{eval_set_id}",
        "label_set_version": "1",
        "dataset": {"dataset_id": "splunk-attack-data+benign", "dataset_version": dataset_version,
                    "evaluation_set_id": eval_set_id, "evaluation_set_checksum": checksum},
        "coverage": {"total_events": len(labels), "complete": bool(reviewer)},
        "labels": labels,
    }
    (out / "labels" / "reviewed_label_set.json").write_text(json.dumps(label_set, indent=2), encoding="utf-8")
    (out / "manifest.json").write_text(json.dumps({
        "evaluation_set_id": eval_set_id, "created_at": now, "counts": counts,
        "evaluation_set_checksum": checksum, "files": files_meta}, indent=2), encoding="utf-8")
    print(f"attack={counts['attack']} benign={counts['benign']} dup_skipped={counts['duplicates_skipped']}")
    print(f"written to {out}")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--eval-set-id", required=True)
    ap.add_argument("--dataset-version", default=datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    ap.add_argument("--reviewer", help="mark labels reviewed (only after spot-checking)")
    args = ap.parse_args()
    build(args.eval_set_id, args.reviewer, args.dataset_version)


if __name__ == "__main__":
    main()
