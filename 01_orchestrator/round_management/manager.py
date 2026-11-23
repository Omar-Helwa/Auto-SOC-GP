"""RoundManager: creates, tracks and closes rounds.

Responsibilities:
  * create a round from a ``round_request`` (the round id is its ``task_id``)
  * enforce the Architecture 1 state order
  * require each state to reference the contract messages it produces
  * count attempts and enforce the retry and timeout limits
  * record every transition with a timestamp and artifact references
  * close the round as completed, failed or inconclusive, storing failures as
    contract-valid ``error_response`` messages

It does NOT call red, blue, the platform or the judge, and it never decides
whether a candidate passes; it only records the decision the judge returned.
"""

from __future__ import annotations

import threading
import uuid
import json
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Union

from .contracts import (
    CONTRACT_VERSION,
    FEEDBACK_RECORD,
    JUDGE_DECISIONS,
    KNOWN_ARTIFACTS,
    SOURCE_COMPONENT,
)
from .errors import (
    DuplicateRoundError,
    InvalidArgumentError,
    InvalidTransitionError,
    IntegrityError,
    MissingArtifactError,
    ROUND_ERROR_CATEGORIES,
    RetryExhaustedError,
    RoundTimedOutError,
    RoundClosedError,
    RoundManagementError,
    RoundNotFoundError,
    make_error_response,
)
from .models import AttemptRecord, RoundConfig, RoundRecord, Transition
from .states import (
    ALLOWED_ARTIFACTS,
    ALLOWED_TRANSITIONS,
    FORWARD_PATH,
    REQUIRED_ARTIFACTS,
    STEP_NUMBER,
    RoundState,
    is_terminal,
    next_forward_state,
)
from .store import RoundStore

Clock = Callable[[], datetime]
IdFactory = Callable[[], str]

VALID_JUDGE_DECISIONS = JUDGE_DECISIONS


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _default_error_id() -> str:
    return str(uuid.uuid4())


class RoundManager:
    def __init__(
        self,
        store: RoundStore,
        clock: Optional[Clock] = None,
        error_id_factory: Optional[IdFactory] = None,
    ) -> None:
        self._store = store
        self._clock = clock or _utc_now
        self._error_id_factory = error_id_factory or _default_error_id
        self._lock = threading.RLock()

    # -- helpers
    def _now(self, not_before: Optional[str] = None) -> str:
        now = self._clock().astimezone(timezone.utc)
        if not_before is not None:
            previous = datetime.fromisoformat(not_before)
            if now < previous:
                now = previous
        return now.isoformat()

    @staticmethod
    def _validate_json(value: Any, field: str) -> None:
        try:
            json.dumps(value, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise InvalidArgumentError(f"{field} must contain only strict JSON values: {exc}") from exc

    def _load(self, round_id: str) -> RoundRecord:
        record = self._store.load(round_id)
        if record is None:
            raise RoundNotFoundError(f"Round not found: {round_id}")
        return record

    def _load_open(self, round_id: str) -> RoundRecord:
        self.verify_integrity(round_id)
        record = self._load(round_id)
        if is_terminal(record.state):
            raise RoundClosedError(
                f"Round {round_id} is closed ({record.state.value}); no further changes allowed"
            )
        return record

    @staticmethod
    def _check_artifacts(
        record: Optional[RoundRecord], to_state: RoundState, artifacts: Optional[Mapping[str, str]]
    ) -> Dict[str, str]:
        """Validate the contract message references given for a state change."""
        given = dict(artifacts or {})
        for name, ref in given.items():
            if name not in KNOWN_ARTIFACTS:
                raise InvalidArgumentError(
                    f"Unknown artifact name {name!r}; expected one of {sorted(KNOWN_ARTIFACTS)}"
                )
            if not isinstance(ref, str) or not ref.strip():
                raise InvalidArgumentError(f"Artifact {name!r} needs a non-empty reference")
            if record is not None and name in record.artifacts:
                raise InvalidArgumentError(f"Artifact {name!r} was already recorded for this round")
        not_allowed = sorted(set(given) - ALLOWED_ARTIFACTS.get(to_state, frozenset()))
        if not_allowed:
            raise InvalidArgumentError(
                f"Artifact(s) {not_allowed} are not allowed when entering {to_state.value}",
                {"state": to_state.value, "not_allowed": not_allowed},
            )
        missing = [name for name in REQUIRED_ARTIFACTS.get(to_state, ()) if name not in given]
        if missing:
            raise MissingArtifactError(
                f"Entering {to_state.value} requires artifact(s): {', '.join(missing)}",
                {"state": to_state.value, "missing_artifacts": missing},
            )
        return given

    def _append(
        self,
        record: RoundRecord,
        to_state: RoundState,
        *,
        detail: str = "",
        artifacts: Optional[Mapping[str, str]] = None,
    ) -> None:
        artifacts = dict(artifacts or {})
        now = self._now(record.transitions[-1].at if record.transitions else None)
        for index, attempt in enumerate(record.attempt_log):
            if attempt.outcome != "running":
                continue
            if attempt.state is to_state and not is_terminal(to_state):
                record.attempt_log[index] = replace(attempt, finished_at=now, outcome="succeeded")
            elif is_terminal(to_state):
                record.attempt_log[index] = replace(
                    attempt,
                    finished_at=now,
                    outcome="failed",
                    error=detail or "round closed before attempt completed",
                    error_category="internal",
                )
        record.transitions.append(
            Transition(
                sequence=len(record.transitions) + 1,
                from_state=record.state,
                to_state=to_state,
                at=now,
                step=STEP_NUMBER.get(to_state),
                detail=detail,
                artifacts=artifacts,
            )
        )
        record.artifacts.update(artifacts)
        record.state = to_state
        record.updated_at = now
        record.step_started_at = now
        record.attempts = {}  # attempt counters are per step
        if is_terminal(to_state):
            record.closed_at = now

    def _make_error(
        self,
        record: RoundRecord,
        category: str,
        message: str,
        *,
        retryable: bool,
        details: Optional[Dict[str, Any]],
        occurred_at: str,
    ) -> Dict[str, Any]:
        """Build the ``error_response`` stored on a failed round."""
        merged = dict(details or {})
        merged["failed_in_state"] = record.state.value
        try:
            return make_error_response(
                category,
                message,
                task_id=record.config.task_id,
                retryable=retryable,
                details=merged,
                error_id=self._error_id_factory(),
                timestamp=occurred_at,
            )
        except ValueError as exc:
            raise RoundManagementError(f"Cannot build a valid error_response: {exc}") from exc

    def _error_time(self, record: RoundRecord) -> str:
        return self._now(record.transitions[-1].at if record.transitions else None)

    # -- lifecycle
    def create_round(self, request: Union[RoundConfig, Dict[str, Any]]) -> RoundRecord:
        """Step 1: open a round. Validates the ``round_request`` and freezes it.

        The round id is the request's ``task_id``; a task_id can open one round.
        """
        config = request if isinstance(request, RoundConfig) else RoundConfig.from_request(request)
        with self._lock:
            now = self._now()
            round_id = config.task_id
            if self._store.load(round_id) is not None:
                raise DuplicateRoundError(f"A round already exists for task_id {round_id}")
            record = RoundRecord(
                round_id=round_id,
                config=config,
                config_fingerprint=config.fingerprint(),
                state=RoundState.CREATED,
                created_at=now,
                updated_at=now,
                step_started_at=now,
            )
            record.transitions.append(
                Transition(
                    sequence=1,
                    from_state=None,
                    to_state=RoundState.CREATED,
                    at=now,
                    step=STEP_NUMBER[RoundState.CREATED],
                    detail="round created with frozen configuration",
                )
            )
            self._store.save(record)
            return self._load(round_id)

    def get_round(self, round_id: str) -> RoundRecord:
        return self._load(round_id)

    def history(self, round_id: str) -> List[Transition]:
        return list(self._load(round_id).transitions)

    def advance(
        self,
        round_id: str,
        to_state: RoundState,
        *,
        detail: str = "",
        artifacts: Optional[Mapping[str, str]] = None,
    ) -> RoundRecord:
        """Move one step forward along the fixed Architecture 1 path.

        ``artifacts`` maps contract names to references for the messages the
        component returned (for example ``{"red_proposal": "audit://..."}``).
        Each state requires specific ones; see ``REQUIRED_ARTIFACTS``.

        Failure and inconclusive exits use ``fail`` / ``mark_inconclusive``;
        completion uses ``complete`` so the judge decision is recorded.
        """
        if to_state in (RoundState.FAILED, RoundState.INCONCLUSIVE, RoundState.COMPLETED):
            raise InvalidTransitionError(
                f"Use fail(), mark_inconclusive() or complete() to move to {to_state.value}"
            )
        with self._lock:
            if self.enforce_timeout(round_id):
                raise RoundTimedOutError(f"Round {round_id} timed out; the late result was not accepted")
            record = self._load_open(round_id)
            self._check_allowed(record, to_state)
            given = self._check_artifacts(record, to_state, artifacts)
            prior_attempts = [a for a in record.attempt_log if a.state is to_state]
            if prior_attempts and prior_attempts[-1].outcome != "succeeded":
                raise InvalidTransitionError(
                    f"The latest {to_state.value} attempt has not succeeded"
                )
            self._append(record, to_state, detail=detail, artifacts=given)
            self._store.save(record)
            return self._load(round_id)

    def _check_allowed(self, record: RoundRecord, to_state: RoundState) -> None:
        if to_state not in ALLOWED_TRANSITIONS[record.state]:
            allowed = sorted(s.value for s in ALLOWED_TRANSITIONS[record.state])
            raise InvalidTransitionError(
                f"Cannot move round {record.round_id} from {record.state.value} to "
                f"{to_state.value}; allowed: {allowed}",
                {"from": record.state.value, "to": to_state.value, "allowed": allowed},
            )

    # --------------------------------------------------------- retries/timeouts
    def begin_attempt(self, round_id: str) -> int:
        """Register an attempt at the current step and return its number (1-based).

        Attempts are keyed by the state this work is expected to produce and
        retained in the audit log after the round advances.
        """
        with self._lock:
            if self.enforce_timeout(round_id):
                raise RoundTimedOutError(f"Round {round_id} timed out before a new attempt started")
            record = self._load_open(round_id)
            target = next_forward_state(record.state)
            if target is RoundState.COMPLETED:
                raise InvalidTransitionError("Completion is recorded with complete(), not as an attempt")
            key = target.value
            used = record.attempts.get(key, 0)
            limit = record.config.max_attempts_per_step
            if any(a.state is target and a.outcome == "running" for a in record.attempt_log):
                raise InvalidTransitionError(f"An attempt for {key} is already running")
            if used >= limit:
                failed = [a for a in record.attempt_log if a.state is target and a.outcome == "failed"]
                category = (failed[-1].error_category if failed else None) or "internal"
                details = {"reason": "retry_exhausted", "state": key, "max_attempts": limit}
                self.fail(
                    round_id,
                    category=category,
                    message=f"Step {key} exhausted {limit} attempt(s)",
                    details=details,
                )
                raise RetryExhaustedError(
                    f"Round {round_id}: {limit} attempt(s) used in state {key}", details, category
                )
            record.attempts[key] = used + 1
            not_before = record.transitions[-1].at
            previous_attempts = [a for a in record.attempt_log if a.state is target]
            if previous_attempts and previous_attempts[-1].finished_at:
                not_before = max(
                    (not_before, previous_attempts[-1].finished_at),
                    key=lambda value: datetime.fromisoformat(value),
                )
            now = self._now(not_before)
            record.attempt_log.append(AttemptRecord(state=target, number=used + 1, started_at=now))
            record.updated_at = now
            self._store.save(record)
            return used + 1

    def finish_attempt(
        self,
        round_id: str,
        outcome: str,
        *,
        error: Optional[str] = None,
        error_category: str = "internal",
        raw_output_ref: Optional[str] = None,
    ) -> RoundRecord:
        """Record an attempt result; exhaust retries as soon as the last fails.

        ``error_category`` is the ``error_response`` category of a failed
        attempt (for example ``dependency`` when the model gateway was down). It
        becomes the round's error category if this was the last allowed attempt.
        """
        if outcome not in ("succeeded", "failed"):
            raise InvalidArgumentError("outcome must be 'succeeded' or 'failed'")
        if outcome == "failed" and (not isinstance(error, str) or not error.strip()):
            raise InvalidArgumentError("error is required for a failed attempt")
        if outcome == "succeeded" and error is not None:
            raise InvalidArgumentError("error is only valid for a failed attempt")
        if error_category not in ROUND_ERROR_CATEGORIES:
            raise InvalidArgumentError(f"Unknown error category: {error_category}")
        if raw_output_ref is not None and (not isinstance(raw_output_ref, str) or not raw_output_ref.strip()):
            raise InvalidArgumentError("raw_output_ref must be a non-empty string when provided")
        with self._lock:
            record = self._load_open(round_id)
            if self.is_timed_out(round_id):
                self.enforce_timeout(round_id)
                raise RoundTimedOutError(f"Round {round_id} timed out before the attempt result was accepted")
            target = next_forward_state(record.state)
            active_index = next(
                (i for i in range(len(record.attempt_log) - 1, -1, -1)
                 if record.attempt_log[i].state is target and record.attempt_log[i].outcome == "running"),
                None,
            )
            if active_index is None:
                raise InvalidTransitionError(f"No running attempt for {target.value}")
            attempt = record.attempt_log[active_index]
            now = self._now(attempt.started_at)
            record.attempt_log[active_index] = replace(
                attempt,
                finished_at=now,
                outcome=outcome,
                error=error,
                error_category=error_category if outcome == "failed" else None,
                raw_output_ref=raw_output_ref,
            )
            record.updated_at = now
            if outcome == "failed" and attempt.number >= record.config.max_attempts_per_step:
                record.error = self._make_error(
                    record,
                    error_category,
                    f"Step {target.value} failed after {attempt.number} attempt(s): {error}",
                    retryable=False,
                    details={"reason": "retry_exhausted", "state": target.value, "max_attempts": attempt.number},
                    occurred_at=now,
                )
                record.outcome = "failed"
                self._append(record, RoundState.FAILED, detail=f"{error_category}: step {target.value} exhausted retries")
            self._store.save(record)
            return self._load(round_id)

    def is_timed_out(self, round_id: str) -> bool:
        record = self._load(round_id)
        if is_terminal(record.state):
            return False
        started = datetime.fromisoformat(record.step_started_at)
        elapsed = (self._clock().astimezone(timezone.utc) - started).total_seconds()
        return elapsed >= record.config.step_timeout_seconds

    def enforce_timeout(self, round_id: str) -> bool:
        """Fail the round with a ``timeout`` error if the current step ran too long."""
        with self._lock:
            if not self.is_timed_out(round_id):
                return False
            record = self._load_open(round_id)
            self.fail(
                round_id,
                category="timeout",
                message=f"Step exceeded {record.config.step_timeout_seconds}s in state "
                f"{record.state.value}",
                retryable=True,
                details={"state": record.state.value, "step_timeout_seconds": record.config.step_timeout_seconds},
            )
            return True

    # -- terminal exits
    def fail(
        self,
        round_id: str,
        category: str,
        message: str,
        *,
        retryable: bool = False,
        details: Optional[Dict[str, Any]] = None,
    ) -> RoundRecord:
        """Close the round as FAILED and store a contract-valid ``error_response``."""
        if category not in ROUND_ERROR_CATEGORIES:
            raise InvalidArgumentError(f"Unknown round error category: {category}")
        if not isinstance(message, str) or not message.strip():
            raise InvalidArgumentError("message must be a non-empty string")
        self._validate_json(details or {}, "error details")
        with self._lock:
            record = self._load_open(round_id)
            record.error = self._make_error(
                record,
                category,
                message,
                retryable=retryable,
                details=details,
                occurred_at=self._error_time(record),
            )
            record.outcome = "failed"
            self._append(record, RoundState.FAILED, detail=f"{category}: {message}")
            self._store.save(record)
            return self._load(round_id)

    def mark_inconclusive(
        self,
        round_id: str,
        reason: str,
        *,
        details: Optional[Dict[str, Any]] = None,
        category: str = "missing_information",
    ) -> RoundRecord:
        """Close the round as INCONCLUSIVE (e.g. evidence missing or incomplete).

        Use this when the orchestrator itself cannot continue because evidence
        is missing or incomplete (see the ``incomplete`` rules in
        ``validation_rules.json``). When the judge returns ``inconclusive``,
        use ``complete()`` instead.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise InvalidArgumentError("reason must be a non-empty string")
        if category not in ROUND_ERROR_CATEGORIES:
            raise InvalidArgumentError(f"Unknown round error category: {category}")
        self._validate_json(details or {}, "inconclusive details")
        with self._lock:
            record = self._load_open(round_id)
            record.outcome = "inconclusive"
            record.error = self._make_error(
                record,
                category,
                reason,
                retryable=False,
                details=details,
                occurred_at=self._error_time(record),
            )
            self._append(record, RoundState.INCONCLUSIVE, detail=reason)
            self._store.save(record)
            return self._load(round_id)

    def complete(
        self, round_id: str, judge_decision: str, feedback_ref: str
    ) -> RoundRecord:
        """Step 8: close the round after the feedback record is stored.

        The decision is whatever the judge returned (``pass``, ``reject`` or
        ``inconclusive``, case-insensitive); this method only records it. A
        judge ``inconclusive`` is a valid judge_result, not an error, so the
        round closes as INCONCLUSIVE with no error stored.

        Like ``advance()``, this honours the step timeout: if the round has been
        in ``judged`` longer than ``step_timeout_seconds``, it is failed with a
        ``timeout`` error and ``RoundTimedOutError`` is raised.
        """
        decision = judge_decision.strip().lower() if isinstance(judge_decision, str) else judge_decision
        if decision not in VALID_JUDGE_DECISIONS:
            raise InvalidArgumentError(
                f"judge_decision must be one of {VALID_JUDGE_DECISIONS}, got {judge_decision!r}"
            )
        if not isinstance(feedback_ref, str) or not feedback_ref.strip():
            raise InvalidArgumentError("feedback_ref is required to close a round")
        with self._lock:
            if self.enforce_timeout(round_id):
                raise RoundTimedOutError(f"Round {round_id} timed out; the late feedback record was not accepted")
            record = self._load_open(round_id)
            if record.state is not RoundState.JUDGED:
                raise InvalidTransitionError(
                    f"Round can only be completed from judged, not {record.state.value}"
                )
            target = RoundState.INCONCLUSIVE if decision == "inconclusive" else RoundState.COMPLETED
            given = self._check_artifacts(record, target, {FEEDBACK_RECORD: feedback_ref})
            record.outcome = decision
            self._append(record, target, detail=f"judge decision: {decision}", artifacts=given)
            self._store.save(record)
            return self._load(round_id)

    # ----------------------------------------------------------------- auditing
    def verify_integrity(self, round_id: str) -> None:
        """Raise IntegrityError if the persisted round record is inconsistent."""
        record = self._load(round_id)
        if record.round_id != record.config.task_id:
            raise IntegrityError(f"Round {round_id}: round id differs from the config task_id")
        if record.config.fingerprint() != record.config_fingerprint:
            raise IntegrityError(f"Round {round_id}: frozen configuration was modified")
        seqs = [t.sequence for t in record.transitions]
        if not seqs or seqs != list(range(1, len(seqs) + 1)):
            raise IntegrityError(f"Round {round_id}: transition sequence is broken")
        if record.transitions[0].from_state is not None or record.transitions[0].to_state is not RoundState.CREATED:
            raise IntegrityError(f"Round {round_id}: history does not begin at created")
        previous: Optional[RoundState] = None
        previous_at: Optional[datetime] = None
        expected_artifacts: Dict[str, str] = {}
        for t in record.transitions:
            if t.from_state != previous:
                raise IntegrityError(f"Round {round_id}: history gap at sequence {t.sequence}")
            if t.from_state is not None and t.to_state not in ALLOWED_TRANSITIONS[t.from_state]:
                raise IntegrityError(
                    f"Round {round_id}: illegal transition recorded at sequence {t.sequence}"
                )
            if t.step != STEP_NUMBER.get(t.to_state):
                raise IntegrityError(f"Round {round_id}: invalid step at sequence {t.sequence}")
            try:
                at = datetime.fromisoformat(t.at)
            except (TypeError, ValueError) as exc:
                raise IntegrityError(f"Round {round_id}: invalid timestamp at sequence {t.sequence}") from exc
            if at.tzinfo is None or (previous_at is not None and at < previous_at):
                raise IntegrityError(f"Round {round_id}: invalid timestamp order at sequence {t.sequence}")
            for name, ref in t.artifacts.items():
                if name not in ALLOWED_ARTIFACTS.get(t.to_state, frozenset()):
                    raise IntegrityError(
                        f"Round {round_id}: artifact {name!r} is not allowed at sequence {t.sequence}"
                    )
                if not isinstance(ref, str) or not ref.strip() or name in expected_artifacts:
                    raise IntegrityError(f"Round {round_id}: invalid artifact {name!r} at sequence {t.sequence}")
                expected_artifacts[name] = ref
            if t.to_state in FORWARD_PATH[1:] and any(
                name not in t.artifacts for name in REQUIRED_ARTIFACTS.get(t.to_state, ())
            ):
                raise IntegrityError(
                    f"Round {round_id}: {t.to_state.value} is missing a required artifact at sequence {t.sequence}"
                )
            previous = t.to_state
            previous_at = at
        if previous != record.state:
            raise IntegrityError(f"Round {round_id}: current state does not match history")
        if record.artifacts != expected_artifacts:
            raise IntegrityError(f"Round {round_id}: artifact index does not match history")

        def parse_timestamp(value: Optional[str], field: str) -> Optional[datetime]:
            if value is None:
                return None
            try:
                parsed = datetime.fromisoformat(value)
            except (TypeError, ValueError) as exc:
                raise IntegrityError(f"Round {round_id}: invalid {field} timestamp") from exc
            if parsed.tzinfo is None:
                raise IntegrityError(f"Round {round_id}: {field} timestamp has no timezone")
            return parsed

        created_at = parse_timestamp(record.created_at, "created_at")
        updated_at = parse_timestamp(record.updated_at, "updated_at")
        step_started_at = parse_timestamp(record.step_started_at, "step_started_at")
        closed_at = parse_timestamp(record.closed_at, "closed_at")
        first_at = datetime.fromisoformat(record.transitions[0].at)
        last_at = datetime.fromisoformat(record.transitions[-1].at)
        if created_at != first_at or step_started_at != last_at or updated_at < last_at:
            raise IntegrityError(f"Round {round_id}: record timestamps disagree with history")
        terminal = is_terminal(record.state)
        if terminal != (closed_at is not None) or (closed_at is not None and closed_at != last_at):
            raise IntegrityError(f"Round {round_id}: closed_at disagrees with terminal state")

        if record.state is RoundState.FAILED:
            consistent = record.outcome == "failed" and record.error is not None
        elif record.state is RoundState.INCONCLUSIVE:
            consistent = record.outcome == "inconclusive"
        elif record.state is RoundState.COMPLETED:
            consistent = record.outcome in ("pass", "reject") and record.error is None
        else:
            consistent = record.outcome is None and record.error is None
        if not consistent:
            raise IntegrityError(f"Round {round_id}: outcome/error disagrees with state")
        if record.error is not None:
            error = record.error
            valid_error = (
                isinstance(error, dict)
                and error.get("contract_version") == CONTRACT_VERSION
                and isinstance(error.get("error_id"), str) and error["error_id"]
                and error.get("category") in ROUND_ERROR_CATEGORIES
                and error.get("source_component") == SOURCE_COMPONENT
                and isinstance(error.get("message"), str) and error["message"]
                and type(error.get("retryable")) is bool
                and isinstance(error.get("details", {}), dict)
                and error.get("task_id") == record.config.task_id
                and error.get("timestamp") is not None
            )
            if not valid_error:
                raise IntegrityError(f"Round {round_id}: stored error is not a valid error_response")
            parse_timestamp(error["timestamp"], "error.timestamp")

        attempt_counts: Dict[RoundState, int] = {}
        running_attempts = []
        for attempt in record.attempt_log:
            if attempt.state not in FORWARD_PATH[1:-1]:
                raise IntegrityError(f"Round {round_id}: attempt targets an invalid state")
            expected_number = attempt_counts.get(attempt.state, 0) + 1
            if type(attempt.number) is not int or attempt.number != expected_number:
                raise IntegrityError(f"Round {round_id}: attempt numbering is broken")
            attempt_counts[attempt.state] = expected_number
            started = parse_timestamp(attempt.started_at, "attempt.started_at")
            finished = parse_timestamp(attempt.finished_at, "attempt.finished_at")
            if attempt.error_category is not None and attempt.error_category not in ROUND_ERROR_CATEGORIES:
                raise IntegrityError(f"Round {round_id}: attempt has an unknown error category")
            if attempt.outcome == "running":
                if finished is not None or attempt.error is not None:
                    raise IntegrityError(f"Round {round_id}: running attempt has completion data")
                running_attempts.append(attempt)
            elif attempt.outcome in ("succeeded", "failed"):
                if finished is None or finished < started:
                    raise IntegrityError(f"Round {round_id}: invalid attempt completion time")
                if attempt.outcome == "failed" and not attempt.error:
                    raise IntegrityError(f"Round {round_id}: failed attempt has no error")
            else:
                raise IntegrityError(f"Round {round_id}: invalid attempt outcome")
        if len(running_attempts) > 1:
            raise IntegrityError(f"Round {round_id}: multiple attempts are running")
        if running_attempts:
            if is_terminal(record.state) or record.state is RoundState.JUDGED:
                raise IntegrityError(f"Round {round_id}: terminal workflow has a running attempt")
            if running_attempts[0].state is not next_forward_state(record.state):
                raise IntegrityError(f"Round {round_id}: running attempt targets the wrong step")

        expected_attempts: Dict[str, int] = {}
        if record.state not in (RoundState.JUDGED,) and not is_terminal(record.state):
            target = next_forward_state(record.state)
            used = attempt_counts.get(target, 0)
            if used:
                expected_attempts[target.value] = used
        if record.attempts != expected_attempts:
            raise IntegrityError(f"Round {round_id}: attempt counters disagree with attempt history")
        if any(count > record.config.max_attempts_per_step for count in attempt_counts.values()):
            raise IntegrityError(f"Round {round_id}: attempt limit was exceeded")

    def error_response(self, round_id: str) -> Optional[Dict[str, Any]]:
        """Return the stored ``error_response`` message for a failed round, else None.

        Also set when the orchestrator closed a round as inconclusive because
        information was missing. A judge-decided ``inconclusive`` has no error;
        read the judge_result artifact for the reasons.
        """
        return self._load(round_id).error

    def pinned_versions(self, round_id: str) -> Dict[str, str]:
        """The version references frozen with this round, for audit and replay."""
        return self._load(round_id).config.pinned_versions()
