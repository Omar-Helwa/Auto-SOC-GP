"""Shared folder layout for the dataset pipeline.

datasets/
  original/                         untouched downloads, never edited by the pipeline
    attacks/splunk_attack_data/<technique>__<scenario>/   manifest.yml + *.log
    attacks/benign/<name>/                                your lab / SOCBED benign logs
    rules/splunk_security_content/detections/...          Splunk detection YAML
    rules/splunk_security_content/macros/...              macro definitions used by the SPL
  prepared/<evaluation_set_id>/      outputs that match 00_shared_contracts
    events/events.jsonl
    events/splunk_hec.jsonl
    labels/reviewed_label_set.json
    detections/<detection_id>.json   round_request.detection objects
    detections/index.json
    manifest.json
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORIGINAL = ROOT / "original"
ATTACKS = ORIGINAL / "attacks" / "splunk_attack_data"
BENIGN = ORIGINAL / "attacks" / "benign"
RULES = ORIGINAL / "rules" / "splunk_security_content"
PREPARED = ROOT / "prepared"
CONTRACTS = ROOT.parents[2] / "00_shared_contracts"


def prepared_dir(eval_set_id: str) -> Path:
    return PREPARED / eval_set_id
