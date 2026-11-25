"""Convert Security Content detections into round_request.detection objects.

A detection is selected when one of its tests.attack_data files is a scenario you
downloaded into original/attacks/splunk_attack_data/. Its SPL macros are expanded
using original/rules/.../macros so the rule_text can run as-is; `*_filter` macros
that are not defined become `search *` (Splunk's default).

Output: prepared/<eval_set_id>/detections/<detection_id>.json and index.json.
Also lists detections whose attack data you have NOT downloaded yet.

Usage:
    python prepare_rules.py --eval-set-id evalset-ps-v1
    python prepare_rules.py --eval-set-id evalset-ps-v1 --technique T1059.001   # list candidates
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import yaml

from paths import ATTACKS, RULES, prepared_dir

SCEN_RE = re.compile(r"datasets/attack_techniques/([^/]+)/([^/]+)/")
MACRO_RE = re.compile(r"`([A-Za-z0-9_\-]+)(?:\(([^`]*)\))?`")


def load_macros() -> dict[str, dict]:
    macros: dict[str, dict] = {}
    for f in (RULES / "macros").rglob("*.yml"):
        m = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        if "name" in m and "definition" in m:
            macros[m["name"]] = m
    # Defined by the Splunk CIM / ES apps, not by security_content.
    macros.setdefault("drop_dm_object_name(1)",
                      {"definition": "rename $object$.* AS *", "arguments": ["object"]})
    return macros


def expand(spl: str, macros: dict[str, dict], depth: int = 0) -> tuple[str, list[str]]:
    """Expand `macro` and `macro(args)`. Returns text and unknown macro names."""
    unknown: list[str] = []
    if depth > 10:
        return spl, unknown

    def repl(m: re.Match) -> str:
        name, args = m.group(1), m.group(2)
        key = f"{name}({len(args.split(','))})" if args is not None else name
        mac = macros.get(key) or macros.get(name)
        if mac is None:
            if name.endswith("_filter"):
                return "search *"
            unknown.append(name)
            return m.group(0)
        text = str(mac["definition"])
        if args is not None:
            for param, val in zip(mac.get("arguments", []), [a.strip() for a in args.split(",")]):
                text = text.replace(f"${param}$", val)
        inner, unk = expand(text, macros, depth + 1)
        unknown.extend(unk)
        return inner

    return MACRO_RE.sub(repl, spl), unknown


def downloaded_scenarios() -> set[str]:
    return {p.name for p in ATTACKS.iterdir() if p.is_dir()} if ATTACKS.exists() else set()


def scenarios_of(det: dict) -> set[str]:
    out = set()
    for test in det.get("tests") or []:
        for ad in test.get("attack_data") or []:
            m = SCEN_RE.search(str(ad.get("data", "")))
            if m:
                out.add(f"{m.group(1)}__{m.group(2)}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--eval-set-id", required=True)
    ap.add_argument("--technique", help="only print detections for this ATT&CK id and their scenarios")
    args = ap.parse_args()

    if not (RULES / "detections").exists():
        raise SystemExit("run download_rules.py first")
    macros = load_macros()
    have = downloaded_scenarios()
    out_dir = prepared_dir(args.eval_set_id) / "detections"
    out_dir.mkdir(parents=True, exist_ok=True)

    index, missing = [], {}
    for f in sorted((RULES / "detections").rglob("*.yml")):
        det = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        if det.get("status") == "deprecated" or "search" not in det or "id" not in det:
            continue
        scen = scenarios_of(det)
        techniques = (det.get("tags") or {}).get("mitre_attack_id") or det.get("mitre_attack_id") or []
        if args.technique:
            if args.technique in techniques:
                print(f"{det['name']}  ->  {', '.join(sorted(scen)) or '(no test data)'}")
            continue
        used = scen & have
        if not used:
            for s in scen:
                missing.setdefault(s, []).append(det["name"])
            continue

        rule_text, unknown = expand(str(det["search"]).strip(), macros)
        detection = {
            "detection_id": det["id"],
            "rule_version": str(det.get("version", "1")),
            "description": " ".join(str(det.get("description", "")).split())[:1000],
            "logic_summary": " ".join(f"{det['name']}. Data sources: {', '.join(det.get('data_source') or [])}. "
                                      f"ATT&CK: {', '.join(techniques)}.".split())[:4000],
            "rule_language": "splunk_spl",
            "rule_text": rule_text[:20000],
        }
        (out_dir / f"{det['id']}.json").write_text(json.dumps(detection, indent=2), encoding="utf-8")
        index.append({
            "detection_id": det["id"], "name": det["name"], "type": det.get("type"),
            "attack_techniques": techniques, "attack_scenarios": sorted(used),
            "original_file": str(f.relative_to(RULES)), "original_search": det["search"],
            "rule_text_sha256": hashlib.sha256(rule_text.encode()).hexdigest(),
            "unresolved_macros": sorted(set(unknown)),
            "uses_datamodel": "datamodel=" in rule_text,
        })

    if args.technique:
        return 0
    (out_dir / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
    print(f"prepared {len(index)} detections in {out_dir}")
    for d in index:
        flags = (" [needs CIM datamodel]" if d["uses_datamodel"] else "") + \
                (f" [unresolved: {', '.join(d['unresolved_macros'])}]" if d["unresolved_macros"] else "")
        print(f"  {d['name']}{flags}")
    if not index:
        print("no detection uses the downloaded attack data; try --technique T1059.001 to see options")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
