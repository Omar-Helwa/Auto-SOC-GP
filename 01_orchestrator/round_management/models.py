"""Data models for round management."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, List, Optional, Tuple

from .contracts import (
    ALLOWED_ACTIONS,
    CONTRACT_VERSION,
    EVIDENCE_TYPES,
    MAX_DESCRIPTION_LENGTH,
    MAX_LOGIC_SUMMARY_LENGTH,
    MAX_RULE_TEXT_LENGTH,
    RULE_LANGUAGES,
    SCENARIO_FAMILIES,
    SHA256_PATTERN,
    TASK_ID_PATTERN,
)
from .errors import InvalidRoundRequestError
from .states import RoundState

# Top-level fields of the round_request contract.
_REQUEST_REQUIRED = ("contract_version", "task_id", "detection", "benign_constraints", "dataset", "criteria", "versions")
_REQUEST_OPTIONAL = ("permitted_evidence_refs", "limits")

DEFAULT_MAX_ATTEMPTS_PER_STEP = 2
DEFAULT_STEP_TIMEOUT_SECONDS = 300


def canonical_json(obj: Any) -> str:
    """Stable JSON used for fingerprints (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _freeze(value: Any) -> Any:
    """Recursively make JSON-like config data immutable."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return copy.deepcopy(value)


def _thaw(value: Any) -> Any:
    """Convert frozen config containers to JSON-serializable containers."""
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return copy.deepcopy(value)


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


class _Problems:
    """Collects validation problems, remembering which ones are absent fields."""

    def __init__(self) -> None:
        self.problems: List[str] = []
        self.missing: List[str] = []

    def add(self, text: str) -> None:
        self.problems.append(text)

    def missing_field(self, path: str) -> None:
        self.problems.append(f"missing field: {path}")
        self.missing.append(path)

    def check_object(
        self, path: str, value: Any, required: Tuple[str, ...], optional: Tuple[str, ...] = ()
    ) -> bool:
        """Check that value is an object with no unknown keys; report absent required keys."""
        if not isinstance(value, Mapping):
            self.add(f"{path} must be an object")
            return False
        for key in required:
            if key not in value:
                self.missing_field(f"{path}.{key}")
        unknown = sorted(str(k) for k in set(value) - set(required) - set(optional))
        if unknown:
            self.add(f"{path}: unknown field(s): {', '.join(unknown)}")
        return True

    def text_fields(self, path: str, value: Mapping, names: Tuple[str, ...]) -> None:
        for name in names:
            if name in value and not _is_text(value[name]):
                self.add(f"{path}.{name} must be a non-empty string")

    def raise_if_any(self) -> None:
        if self.problems:
            raise InvalidRoundRequestError(self.problems, self.missing)


def _validate_detection(p: _Problems, detection: Any) -> None:
    required = ("detection_id", "rule_version", "logic_summary", "rule_language", "rule_text")
    if not p.check_object("detection", detection, required, ("description",)):
        return
    p.text_fields("detection", detection, required)
    if "description" in detection and not isinstance(detection["description"], str):
        p.add("detection.description must be a string")
    for name, limit in (
        ("description", MAX_DESCRIPTION_LENGTH),
        ("logic_summary", MAX_LOGIC_SUMMARY_LENGTH),
        ("rule_text", MAX_RULE_TEXT_LENGTH),
    ):
        value = detection.get(name)
        if isinstance(value, str) and len(value) > limit:
            p.add(f"detection.{name} must be at most {limit} characters")
    if _is_text(detection.get("rule_language")) and detection["rule_language"] not in RULE_LANGUAGES:
        p.add(f"detection.rule_language must be one of {list(RULE_LANGUAGES)}")


def _validate_constraints(p: _Problems, constraints: Any) -> None:
    required = ("allowed_scenario_families", "max_workflow_steps", "allowed_actions")
    if not p.check_object("benign_constraints", constraints, required, ("forbidden_notes",)):
        return
    for name, allowed in (("allowed_scenario_families", SCENARIO_FAMILIES), ("allowed_actions", ALLOWED_ACTIONS)):
        if name not in constraints:
            continue
        items = constraints[name]
        if not isinstance(items, (list, tuple)) or not items:
            p.add(f"benign_constraints.{name} must be a non-empty list")
        elif any(item not in allowed for item in items):
            p.add(f"benign_constraints.{name} may only contain {list(allowed)}")
    steps = constraints.get("max_workflow_steps")
    if "max_workflow_steps" in constraints and (type(steps) is not int or not 1 <= steps <= 10):
        p.add("benign_constraints.max_workflow_steps must be an integer from 1 to 10")
    notes = constraints.get("forbidden_notes")
    if "forbidden_notes" in constraints and (
        not isinstance(notes, (list, tuple)) or any(not isinstance(n, str) for n in notes)
    ):
        p.add("benign_constraints.forbidden_notes must be a list of strings")


def _validate_dataset(p: _Problems, dataset: Any) -> None:
    required = ("dataset_id", "dataset_version", "evaluation_set_id")
    if not p.check_object("dataset", dataset, required, ("evaluation_set_checksum",)):
        return
    p.text_fields("dataset", dataset, required)
    checksum = dataset.get("evaluation_set_checksum")
    if "evaluation_set_checksum" in dataset and not (
        isinstance(checksum, str) and SHA256_PATTERN.match(checksum)
    ):
        p.add("dataset.evaluation_set_checksum must be a SHA-256 hex string")


def _validate_criteria(p: _Problems, criteria: Any) -> None:
    required = ("criteria_id", "criteria_version", "thresholds")
    if not p.check_object("criteria", criteria, required):
        return
    p.text_fields("criteria", criteria, ("criteria_id", "criteria_version"))
    if "thresholds" in criteria and (not isinstance(criteria["thresholds"], Mapping) or not criteria["thresholds"]):
        p.add("criteria.thresholds must be a non-empty object")


def _validate_versions(p: _Problems, versions: Any) -> None:
    required = ("red_prompt", "blue_prompt", "model_id", "contracts")
    if not p.check_object("versions", versions, required, ("model_date",)):
        return
    p.text_fields("versions", versions, required + ("model_date",))


def _validate_evidence_refs(p: _Problems, refs: Any) -> None:
    if not isinstance(refs, (list, tuple)):
        p.add("permitted_evidence_refs must be a list")
        return
    for index, ref in enumerate(refs):
        path = f"permitted_evidence_refs[{index}]"
        if not p.check_object(path, ref, ("evidence_id", "evidence_type"), ("provenance_ref",)):
            continue
        p.text_fields(path, ref, ("evidence_id",))
        if "evidence_type" in ref and ref["evidence_type"] not in EVIDENCE_TYPES:
            p.add(f"{path}.evidence_type must be one of {list(EVIDENCE_TYPES)}")
        if "provenance_ref" in ref and not isinstance(ref["provenance_ref"], str):
            p.add(f"{path}.provenance_ref must be a string")


@dataclass(frozen=True)
class RoundConfig:
    """Everything that is frozen when a round is created.

    This is the ``round_request`` contract (see
    ``00_shared_contracts/round_request``): task identifier, detection, benign
    constraints, dataset, judge criteria and version references. Retry and
    timeout limits are frozen too, so a replay behaves the same way.

    ``task_id`` is the round identifier used everywhere in the contracts.
    """

    task_id: str
    detection: Dict[str, Any]
    benign_constraints: Dict[str, Any]
    dataset: Dict[str, Any]
    criteria: Dict[str, Any]
    versions: Dict[str, str]
    permitted_evidence_refs: Tuple[Dict[str, Any], ...] = ()
    max_attempts_per_step: int = DEFAULT_MAX_ATTEMPTS_PER_STEP
    step_timeout_seconds: int = DEFAULT_STEP_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        p = _Problems()
        if not isinstance(self.task_id, str) or not TASK_ID_PATTERN.match(self.task_id):
            p.add("task_id must be a non-empty string of letters, digits, '.', '_' or '-'")
        _validate_detection(p, self.detection)
        _validate_constraints(p, self.benign_constraints)
        _validate_dataset(p, self.dataset)
        _validate_criteria(p, self.criteria)
        _validate_versions(p, self.versions)
        _validate_evidence_refs(p, self.permitted_evidence_refs)
        if type(self.max_attempts_per_step) is not int or self.max_attempts_per_step < 1:
            p.add("limits.max_attempts_per_step must be an integer >= 1")
        if type(self.step_timeout_seconds) is not int or self.step_timeout_seconds < 1:
            p.add("limits.step_timeout_seconds must be an integer >= 1")
        p.raise_if_any()
        for name in ("detection", "benign_constraints", "dataset", "criteria", "versions", "permitted_evidence_refs"):
            try:
                json.dumps(_thaw(getattr(self, name)), allow_nan=False)
            except (TypeError, ValueError) as exc:
                raise InvalidRoundRequestError([f"{name} must contain only strict JSON values: {exc}"]) from exc
        # Freeze nested containers so callers cannot mutate a supposedly frozen config.
        for name in ("detection", "benign_constraints", "dataset", "criteria", "versions"):
            object.__setattr__(self, name, _freeze(getattr(self, name)))
        object.__setattr__(self, "permitted_evidence_refs", _freeze(list(self.permitted_evidence_refs)))

    @classmethod
    def from_request(cls, request: Dict[str, Any]) -> "RoundConfig":
        """Build a config from a ``round_request`` message, rejecting anything the contract does not allow."""
        if not isinstance(request, Mapping):
            raise InvalidRoundRequestError(["round request must be an object"])
        p = _Problems()
        for key in _REQUEST_REQUIRED:
            if key not in request:
                p.missing_field(key)
        unknown = sorted(str(k) for k in set(request) - set(_REQUEST_REQUIRED) - set(_REQUEST_OPTIONAL))
        if unknown:
            p.add(f"unknown field(s): {', '.join(unknown)}")
        if "contract_version" in request and request["contract_version"] != CONTRACT_VERSION:
            p.add(f"contract_version must be {CONTRACT_VERSION!r}")
        limits: Mapping = {}
        if "limits" in request:
            if p.check_object("limits", request["limits"], (), ("max_attempts_per_step", "step_timeout_seconds")):
                limits = request["limits"]
        p.raise_if_any()
        return cls(
            task_id=request["task_id"],
            detection=request["detection"],
            benign_constraints=request["benign_constraints"],
            dataset=request["dataset"],
            criteria=request["criteria"],
            versions=request["versions"],
            permitted_evidence_refs=tuple(request.get("permitted_evidence_refs", ())),
            max_attempts_per_step=limits.get("max_attempts_per_step", DEFAULT_MAX_ATTEMPTS_PER_STEP),
            step_timeout_seconds=limits.get("step_timeout_seconds", DEFAULT_STEP_TIMEOUT_SECONDS),
        )

    def to_dict(self) -> Dict[str, Any]:
        """The frozen config as a ``round_request`` message (always with explicit limits)."""
        data: Dict[str, Any] = {
            "contract_version": CONTRACT_VERSION,
            "task_id": self.task_id,
            "detection": _thaw(self.detection),
            "benign_constraints": _thaw(self.benign_constraints),
            "dataset": _thaw(self.dataset),
            "criteria": _thaw(self.criteria),
            "versions": _thaw(self.versions),
            "limits": {
                "max_attempts_per_step": self.max_attempts_per_step,
                "step_timeout_seconds": self.step_timeout_seconds,
            },
        }
        if self.permitted_evidence_refs:
            data["permitted_evidence_refs"] = _thaw(self.permitted_evidence_refs)
        return data

    def to_red_input(self) -> Dict[str, Any]:
        """Derive the ``red_input`` message for the red role from this config.

        Red gets the detection's description, not its executable rule text.
        """
        detection = {
            key: self.detection[key]
            for key in ("detection_id", "rule_version", "description", "logic_summary")
            if key in self.detection
        }
        red_input: Dict[str, Any] = {
            "contract_version": CONTRACT_VERSION,
            "task_id": self.task_id,
            "detection": detection,
            "benign_constraints": _thaw(self.benign_constraints),
            "prompt_version": self.versions["red_prompt"],
            "output_contract_version": CONTRACT_VERSION,
        }
        if self.permitted_evidence_refs:
            red_input["permitted_evidence_refs"] = _thaw(self.permitted_evidence_refs)
        return red_input

    def pinned_versions(self) -> Dict[str, str]:
        """Every version reference that must be recorded so the round can be reproduced."""
        pinned = {
            "contracts": self.versions["contracts"],
            "red_prompt": self.versions["red_prompt"],
            "blue_prompt": self.versions["blue_prompt"],
            "model_id": self.versions["model_id"],
            "rule_version": self.detection["rule_version"],
            "dataset_version": self.dataset["dataset_version"],
            "evaluation_set_id": self.dataset["evaluation_set_id"],
            "criteria_version": self.criteria["criteria_version"],
        }
        if "model_date" in self.versions:
            pinned["model_date"] = self.versions["model_date"]
        return pinned

    def fingerprint(self) -> str:
        return hashlib.sha256(canonical_json(self.to_dict()).encode("utf-8")).hexdigest()

    def __hash__(self) -> int:
        return hash(self.fingerprint())


@dataclass(frozen=True)
class Transition:
    """One entry in a round's append-only history."""

    sequence: int
    from_state: Optional[RoundState]
    to_state: RoundState
    at: str  # ISO-8601 UTC
    step: Optional[int] = None
    detail: str = ""
    # Contract messages received with this transition: name -> reference.
    artifacts: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence": self.sequence,
            "from_state": self.from_state.value if self.from_state else None,
            "to_state": self.to_state.value,
            "at": self.at,
            "step": self.step,
            "detail": self.detail,
            "artifacts": dict(self.artifacts),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Transition":
        artifacts = dict(data.get("artifacts") or {})
        if data.get("artifact_name") and data.get("artifact_ref"):  # records written before artifacts became a map
            artifacts[data["artifact_name"]] = data["artifact_ref"]
        return cls(
            sequence=data["sequence"],
            from_state=RoundState(data["from_state"]) if data.get("from_state") else None,
            to_state=RoundState(data["to_state"]),
            at=data["at"],
            step=data.get("step"),
            detail=data.get("detail", ""),
            artifacts=artifacts,
        )


@dataclass(frozen=True)
class AttemptRecord:
    """Append-only record of one attempt to produce a workflow state."""

    state: RoundState
    number: int
    started_at: str
    finished_at: Optional[str] = None
    outcome: str = "running"  # running | succeeded | failed
    error: Optional[str] = None
    # error_response category of a failed attempt (one of ERROR_CATEGORIES).
    error_category: Optional[str] = None
    raw_output_ref: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "number": self.number,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "outcome": self.outcome,
            "error": self.error,
            "error_category": self.error_category,
            "raw_output_ref": self.raw_output_ref,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttemptRecord":
        return cls(
            state=RoundState(data["state"]),
            number=data["number"],
            started_at=data["started_at"],
            finished_at=data.get("finished_at"),
            outcome=data.get("outcome", "running"),
            error=data.get("error"),
            error_category=data.get("error_category"),
            raw_output_ref=data.get("raw_output_ref"),
        )


@dataclass
class RoundRecord:
    """Mutable runtime state of a round. Only RoundManager should change it."""

    round_id: str  # equals config.task_id
    config: RoundConfig
    config_fingerprint: str
    state: RoundState
    created_at: str
    updated_at: str
    step_started_at: str
    closed_at: Optional[str] = None
    revision: int = 0
    transitions: List[Transition] = field(default_factory=list)
    attempt_log: List[AttemptRecord] = field(default_factory=list)
    # References (not payloads) to the contract messages each component
    # produced, keyed by contract name, e.g. {"red_proposal": "audit://raw/abc123"}.
    artifacts: Dict[str, str] = field(default_factory=dict)
    # Attempts used in the current state's step.
    attempts: Dict[str, int] = field(default_factory=dict)
    outcome: Optional[str] = None  # pass | reject | inconclusive | failed
    # An error_response contract message when the round failed (or was closed as
    # inconclusive because information was missing); otherwise None.
    error: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "round_id": self.round_id,
            "config": self.config.to_dict(),
            "config_fingerprint": self.config_fingerprint,
            "state": self.state.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "step_started_at": self.step_started_at,
            "closed_at": self.closed_at,
            "revision": self.revision,
            "transitions": [t.to_dict() for t in self.transitions],
            "attempt_log": [attempt.to_dict() for attempt in self.attempt_log],
            "artifacts": dict(self.artifacts),
            "attempts": dict(self.attempts),
            "outcome": self.outcome,
            "error": copy.deepcopy(self.error),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RoundRecord":
        return cls(
            round_id=data["round_id"],
            config=RoundConfig.from_request(data["config"]),
            config_fingerprint=data["config_fingerprint"],
            state=RoundState(data["state"]),
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            step_started_at=data["step_started_at"],
            closed_at=data.get("closed_at"),
            revision=data.get("revision", 0),
            transitions=[Transition.from_dict(t) for t in data.get("transitions", [])],
            attempt_log=[AttemptRecord.from_dict(a) for a in data.get("attempt_log", [])],
            artifacts=dict(data.get("artifacts", {})),
            attempts=dict(data.get("attempts", {})),
            outcome=data.get("outcome"),
            error=copy.deepcopy(data.get("error")),
        )
