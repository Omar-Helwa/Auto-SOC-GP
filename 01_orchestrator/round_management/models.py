"""Data models for round management."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, List, Optional

from .errors import InvalidRoundRequestError
from .states import RoundState

# Version references every round must pin so it can be reproduced later.
REQUIRED_VERSION_KEYS = ("prompt", "model", "rule", "dataset", "criteria", "contracts")

_REQUEST_KEYS = {
    "task_id",
    "detection",
    "dataset_ref",
    "criteria",
    "versions",
    "max_attempts_per_step",
    "step_timeout_seconds",
}


def canonical_json(obj: Any) -> str:
    """Stable JSON used for fingerprints (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _freeze(value: Any) -> Any:
    """Recursively make JSON-like config data immutable."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return copy.deepcopy(value)


def _thaw(value: Any) -> Any:
    """Convert frozen config containers to JSON-serializable containers."""
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return copy.deepcopy(value)


@dataclass(frozen=True)
class RoundConfig:
    """Everything that is frozen when a round is created.

    Mirrors the ``round_request`` contract: task identifier, detection,
    dataset reference, criteria and version references. Retry and timeout
    limits are frozen too, so a replay behaves the same way.
    """

    task_id: str
    detection: Dict[str, Any]
    dataset_ref: str
    criteria: Dict[str, Any]
    versions: Dict[str, str]
    max_attempts_per_step: int = 2
    step_timeout_seconds: int = 300

    def __post_init__(self) -> None:
        problems: List[str] = []
        if not isinstance(self.task_id, str) or not self.task_id.strip():
            problems.append("task_id must be a non-empty string")
        if not isinstance(self.detection, Mapping) or not self.detection:
            problems.append("detection must be a non-empty object")
        if not isinstance(self.dataset_ref, str) or not self.dataset_ref.strip():
            problems.append("dataset_ref must be a non-empty string")
        if not isinstance(self.criteria, Mapping) or not self.criteria:
            problems.append("criteria must be a non-empty object")
        if not isinstance(self.versions, Mapping):
            problems.append("versions must be an object")
        else:
            for key in REQUIRED_VERSION_KEYS:
                value = self.versions.get(key)
                if not isinstance(value, str) or not value.strip():
                    problems.append(f"versions.{key} is required")
        if type(self.max_attempts_per_step) is not int or self.max_attempts_per_step < 1:
            problems.append("max_attempts_per_step must be an integer >= 1")
        if type(self.step_timeout_seconds) is not int or self.step_timeout_seconds < 1:
            problems.append("step_timeout_seconds must be an integer >= 1")
        if problems:
            raise InvalidRoundRequestError(problems)
        for name, value in (("detection", self.detection), ("criteria", self.criteria), ("versions", self.versions)):
            try:
                json.dumps(_thaw(value), allow_nan=False)
            except (TypeError, ValueError) as exc:
                raise InvalidRoundRequestError([f"{name} must contain only strict JSON values: {exc}"]) from exc
        # Freeze nested containers so callers cannot mutate a supposedly frozen config.
        object.__setattr__(self, "detection", _freeze(self.detection))
        object.__setattr__(self, "criteria", _freeze(self.criteria))
        object.__setattr__(self, "versions", _freeze(self.versions))

    @classmethod
    def from_request(cls, request: Dict[str, Any]) -> "RoundConfig":
        """Build a config from a round_request dict, rejecting unknown fields."""
        if not isinstance(request, dict):
            raise InvalidRoundRequestError(["round request must be an object"])
        unknown = sorted(set(request) - _REQUEST_KEYS)
        if unknown:
            raise InvalidRoundRequestError([f"unknown field(s): {', '.join(unknown)}"])
        missing = [k for k in ("task_id", "detection", "dataset_ref", "criteria", "versions") if k not in request]
        if missing:
            raise InvalidRoundRequestError([f"missing field(s): {', '.join(missing)}"])
        return cls(**request)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "detection": _thaw(self.detection),
            "dataset_ref": self.dataset_ref,
            "criteria": _thaw(self.criteria),
            "versions": _thaw(self.versions),
            "max_attempts_per_step": self.max_attempts_per_step,
            "step_timeout_seconds": self.step_timeout_seconds,
        }

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
    artifact_name: Optional[str] = None
    artifact_ref: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence": self.sequence,
            "from_state": self.from_state.value if self.from_state else None,
            "to_state": self.to_state.value,
            "at": self.at,
            "step": self.step,
            "detail": self.detail,
            "artifact_name": self.artifact_name,
            "artifact_ref": self.artifact_ref,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Transition":
        return cls(
            sequence=data["sequence"],
            from_state=RoundState(data["from_state"]) if data.get("from_state") else None,
            to_state=RoundState(data["to_state"]),
            at=data["at"],
            step=data.get("step"),
            detail=data.get("detail", ""),
            artifact_name=data.get("artifact_name"),
            artifact_ref=data.get("artifact_ref"),
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
    raw_output_ref: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "number": self.number,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "outcome": self.outcome,
            "error": self.error,
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
            raw_output_ref=data.get("raw_output_ref"),
        )


@dataclass
class RoundRecord:
    """Mutable runtime state of a round. Only RoundManager should change it."""

    round_id: str
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
    # References (not payloads) to what each component produced, e.g.
    # {"red_proposal": "audit://raw/abc123"}.
    artifacts: Dict[str, str] = field(default_factory=dict)
    # Attempts used in the current state's step.
    attempts: Dict[str, int] = field(default_factory=dict)
    outcome: Optional[str] = None  # pass | reject | inconclusive | failed
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
            config=RoundConfig(**data["config"]),
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
