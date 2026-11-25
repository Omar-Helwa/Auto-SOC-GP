"""Check prepared/<eval_set_id>/ against 00_shared_contracts.

Usage:
    python validate_prepared.py --eval-set-id evalset-ps-v1
"""
from __future__ import annotations

import argparse
import json

import jsonschema

from paths import CONTRACTS, prepared_dir


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval-set-id", required=True)
    out = prepared_dir(ap.parse_args().eval_set_id)

    rr = json.loads((CONTRACTS / "round_request" / "round_request.schema.json").read_text(encoding="utf-8"))
    det_schema = rr["properties"]["detection"]
    ok = 0
    for f in sorted((out / "detections").glob("*.json")):
        if f.name == "index.json":
            continue
        jsonschema.validate(json.loads(f.read_text(encoding="utf-8")), det_schema)
        ok += 1
    print(f"detections valid against round_request.detection: {ok}")

    ls_schema = json.loads((CONTRACTS / "telemetry_evidence" / "reviewed_label_set.schema.json").read_text(encoding="utf-8"))
    labels = json.loads((out / "labels" / "reviewed_label_set.json").read_text(encoding="utf-8"))
    jsonschema.validate(labels, ls_schema)
    print(f"reviewed_label_set valid: {len(labels['labels'])} labels")

    index = json.loads((out / "detections" / "index.json").read_text(encoding="utf-8"))
    unresolved = [d["name"] for d in index if d["unresolved_macros"]]
    print(f"detections with unresolved macros: {len(unresolved)} {unresolved}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
