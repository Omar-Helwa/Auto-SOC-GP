import os, json
from functools import lru_cache
from pathlib import Path
from collections import Counter
from typing import Any, Mapping
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from evaluation.judge import evaluate

# Resolved from this file's location, so it works no matter which folder Python is started from.
JUDGE_ROOT = Path(__file__).resolve().parents[2]          # .../04_deterministic_judge
DEFAULT_CONTRACTS_DIR = JUDGE_ROOT.parent / "00_shared_contracts"
JUDGE_INPUT_ID = "autosoc://contracts/judge_input/0.1.0"
JUDGE_RESULT_ID = "autosoc://contracts/judge_result/0.1.0"

INVALID = "invalid"
INCOMPLETE = "incomplete"

def run_judge(judge_input: Mapping[str, Any]):
    """Orchestrator entry point: takes one judge_input bundle and returns its judge_result."""
    result = {"contract_version": contract_version(JUDGE_RESULT_ID),
              **evaluate(judge_input, validate_judge_input(judge_input))}
    errors = [error.message for error in validator(JUDGE_RESULT_ID).iter_errors(result)]
    if errors:
        raise ValueError(f"judge result violates judge_result contract: {errors}")
    return result

def validate_judge_input(judge_input: Any):
    """Return all failures for a bundle; an empty list means it can be judged."""
    if not isinstance(judge_input, Mapping):
        return [_failure("INPUT", INVALID, "judge input must be an object")]
    failures = _schema_failures(judge_input)
    if failures:
        # Cross-artifact rules assume schema-valid artifacts.
        return failures
    return _rule_failures(judge_input)

# ------- helpers

def _failure(code: str, kind: str, message: str):
    return {"code": code, "kind": kind, "message": message}

def _schema_failures(judge_input: Mapping[str, Any]):
    errors = sorted(validator(JUDGE_INPUT_ID).iter_errors(judge_input), key=lambda e: list(map(str, e.absolute_path)))
    failures = []
    for error in errors:
        path = ".".join(str(part) for part in error.absolute_path) or "judge_input"
        code = "CRITERIA" if path.startswith("criteria") else "SCHEMA"
        failures.append(_failure(code, INVALID, f"{path}: {error.message}"))
    return failures

def _duplicates(values):
    return sorted(value for value, count in Counter(values).items() if count > 1)

def _rule_failures(judge_input: Mapping[str, Any]):
    """Rules from validation_rules.json that JSON Schema cannot express."""
    baseline = judge_input["baseline_match_set"]
    candidate = judge_input["candidate_match_set"]
    labels = judge_input["reviewed_label_set"]
    failures = []

    # MS-1: unique event_id per match set.
    for side, artifact in (("baseline", baseline), ("candidate", candidate)):
        duplicates = _duplicates(match["event_id"] for match in artifact["matches"])
        if duplicates:
            failures.append(_failure("MS-1", INVALID, f"{side} matches have duplicate event_id values: {duplicates}"))

    # LS-1 / LS-2 / LS-3: label-set integrity.
    label_ids = [item["event_id"] for item in labels["labels"]]
    duplicates = _duplicates(label_ids)
    if duplicates:
        failures.append(_failure("LS-1", INVALID, f"reviewed labels have duplicate event_id values: {duplicates}"))
    total = labels["coverage"]["total_events"]
    if labels["coverage"]["complete"] and len(label_ids) != total:
        failures.append(_failure("LS-2", INVALID,
                                 f"coverage.complete is true but {len(label_ids)} labels != total_events {total}"))
    if len(label_ids) > total:
        failures.append(_failure("LS-3", INVALID, f"{len(label_ids)} labels exceed total_events {total}"))

    # X-1: roles are in the right slots.
    if baseline["role"] != "baseline":
        failures.append(_failure("X-1", INVALID, f"baseline_match_set has role '{baseline['role']}'"))
    if candidate["role"] != "candidate":
        failures.append(_failure("X-1", INVALID, f"candidate_match_set has role '{candidate['role']}'"))

    if failures:
        return failures

    # X-2: same round, detection, dataset, and frozen evaluation set everywhere.
    for name in ("task_id", "detection_id"):
        values = {"bundle": judge_input[name], "baseline": baseline[name], "candidate": candidate[name]}
        if len(set(values.values())) > 1:
            failures.append(_failure("X-2", INCOMPLETE, f"{name} differs: {values}"))
    for name in ("dataset_id", "dataset_version", "evaluation_set_id", "evaluation_set_checksum"):
        values = {
            "baseline": baseline["dataset"].get(name),
            "candidate": candidate["dataset"].get(name),
            "reviewed_labels": labels["dataset"].get(name),
        }
        if name == "evaluation_set_checksum":
            values = {key: value for key, value in values.items() if value is not None}
        if len(set(values.values())) > 1:
            failures.append(_failure("X-2", INCOMPLETE, f"dataset.{name} differs: {values}"))

    # X-4: every matched event has a label.
    labelled = set(label_ids)
    for side, artifact in (("baseline", baseline), ("candidate", candidate)):
        unlabelled = sorted({match["event_id"] for match in artifact["matches"]} - labelled)
        if unlabelled:
            failures.append(_failure("X-4", INCOMPLETE, f"{side} matched events have no label: {unlabelled}"))

    # X-5: both executions completed.
    for side, artifact in (("baseline", baseline), ("candidate", candidate)):
        status = artifact["execution"]["status"]
        if status != "completed":
            failures.append(_failure("X-5", INCOMPLETE, f"{side} execution status is '{status}', not 'completed'"))

    # X-6: coverage complete and every label reviewed.
    if not labels["coverage"]["complete"]:
        failures.append(_failure("X-6", INCOMPLETE,
                                 f"label coverage is marked incomplete ({len(label_ids)} labels for {total} events)"))
    not_reviewed = sorted(item["event_id"] for item in labels["labels"] if item["review"]["status"] != "reviewed")
    if not_reviewed:
        failures.append(_failure("X-6", INCOMPLETE, f"labels not in 'reviewed' status: {not_reviewed}"))

    return failures

# ---- shared contract schemas

def _contracts_dir():
    return Path(os.environ.get("AUTOSOC_CONTRACTS_DIR", DEFAULT_CONTRACTS_DIR))

@lru_cache(maxsize=None)
def _registry_for(directory: str):
    schemas = {}
    for path in sorted(Path(directory).rglob("*.schema.json")):
        loaded = json.loads(path.read_text(encoding="utf-8-sig"))
        if "$id" in loaded:
            schemas[loaded["$id"]] = loaded
    registry = Registry().with_resources(
        (schema_id, Resource.from_contents(loaded)) for schema_id, loaded in schemas.items()
    )
    return schemas, registry

def _schema(schema_id: str):
    schemas, _ = _registry_for(str(_contracts_dir()))
    if schema_id not in schemas:
        raise FileNotFoundError(f"shared contract {schema_id} not found under {_contracts_dir()}")
    return schemas[schema_id]

def contract_version(schema_id: str):
    """Return the contract_version a schema requires (its properties.contract_version.const)."""
    return _schema(schema_id)["properties"]["contract_version"]["const"]

def validator(schema_id: str):
    _, registry = _registry_for(str(_contracts_dir()))
    return Draft202012Validator(_schema(schema_id), registry=registry)
