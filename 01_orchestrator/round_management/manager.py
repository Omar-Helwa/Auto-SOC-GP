"""RoundManager: creates, tracks and closes rounds.

Responsibilities:
  * create a round with a fixed identifier and frozen configuration
  * enforce the Architecture 1 state order
  * count attempts and enforce the retry and timeout limits
  * record every transition with a timestamp and artifact reference
  * close the round as completed, failed or inconclusive

It does NOT call red, blue, the platform or the judge, and it never decides
whether a candidate passes; it only records the decision the judge returned.
"""

from __future__ import annotations

import threading
import uuid
import json
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Union

from .errors import (
    InvalidArgumentError,
    InvalidTransitionError,
    IntegrityError,
    ROUND_ERROR_CATEGORIES,
    RetryExhaustedError,
    RoundTimedOutError,
    RoundClosedError,
    RoundNotFoundError,
    RoundManagementError,
)
from .models import AttemptRecord, RoundConfig, RoundRecord, Transition
from .states import (
    ALLOWED_TRANSITIONS,
    FORWARD_PATH,
    STEP_NUMBER,
    RoundState,
    is_terminal,
    next_forward_state,
)
from .store import RoundStore

Clock = Callable[[], datetime]
IdFactory = Callable[[], str]

VALID_JUDGE_DECISIONS = ("pass", "reject", "inconclusive")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _default_id() -> str:
    return f"round-{uuid.uuid4().hex[:12]}"


class RoundManager:
    def __init__(
        self,
        store: RoundStore,
        clock: Optional[Clock] = None,
        id_factory: Optional[IdFactory] = None,
    ) -> None:
        self._store = store
        self._clock = clock or _utc_now
        self._id_factory = id_factory or _default_id
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

    def _append(
        self,
        record: RoundRecord,
        to_state: RoundState,
        *,
        detail: str = "",
        artifact_name: Optional[str] = None,
        artifact_ref: Optional[str] = None,
    ) -> None:
        now = self._now(record.transitions[-1].at if record.transitions else None)
        for index, attempt in enumerate(record.attempt_log):
            if attempt.outcome != "running":
                continue
            if attempt.state is to_state and not is_terminal(to_state):
                record.attempt_log[index] = replace(
                    attempt,
                    finished_at=now,
                    outcome="succeeded",
                    raw_output_ref=artifact_ref or attempt.raw_output_ref,
                )
            elif is_terminal(to_state):
                record.attempt_log[index] = replace(
                    attempt,
                    finished_at=now,
                    outcome="failed",
                    error=detail or "round closed before attempt completed",
                )
        record.transitions.append(
            Transition(
                sequence=len(record.transitions) + 1,
                from_state=record.state,
                to_state=to_state,
                at=now,
                step=STEP_NUMBER.get(to_state),
                detail=detail,
                artifact_name=artifact_name,
                artifact_ref=artifact_ref,
            )
        )
        if artifact_name and artifact_ref:
            record.artifacts[artifact_name] = artifact_ref
        record.state = to_state
        record.updated_at = now
        record.step_started_at = now
        record.attempts = {}  # attempt counters are per step
        if is_terminal(to_state):
            record.closed_at = now

    # -- lifecycle
    def create_round(self, request: Union[RoundConfig, Dict[str, Any]]) -> RoundRecord:
        """Step 1: open a round. Validates and freezes the configuration."""
        config = request if isinstance(request, RoundConfig) else RoundConfig.from_request(request)
        with self._lock:
            now = self._now()
            round_id = self._id_factory()
            if self._store.load(round_id) is not None:
                raise RoundManagementError(f"Round id already exists: {round_id}")
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
        artifact_name: Optional[str] = None,
        artifact_ref: Optional[str] = None,
    ) -> RoundRecord:
        """Move one step forward along the fixed Architecture 1 path.

        Failure and inconclusive exits use ``fail`` / ``mark_inconclusive``;
        completion uses ``complete`` so the judge decision is recorded.
        """
        if to_state in (RoundState.FAILED, RoundState.INCONCLUSIVE, RoundState.COMPLETED):
            raise InvalidTransitionError(
                f"Use fail(), mark_inconclusive() or complete() to move to {to_state.value}"
            )
        if (artifact_name is None) != (artifact_ref is None):
            raise InvalidArgumentError("artifact_name and artifact_ref must be given together")
        with self._lock:
            if self.enforce_timeout(round_id):
                raise RoundTimedOutError(f"Round {round_id} timed out; the late result was not accepted")
            record = self._load_open(round_id)
            self._check_allowed(record, to_state)
            prior_attempts = [a for a in record.attempt_log if a.state is to_state]
            if prior_attempts and prior_attempts[-1].outcome != "succeeded":
                raise InvalidTransitionError(
                    f"The latest {to_state.value} attempt has not succeeded"
                )
            self._append(
                record,
                to_state,
                detail=detail,
                artifact_name=artifact_name,
                artifact_ref=artifact_ref,
            )
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
                self.fail(
                    round_id,
                    category="retry",
                    message=f"Step {key} exhausted {limit} attempt(s)",
                    details={"state": key, "max_attempts": limit},
                )
                raise RetryExhaustedError(
                    f"Round {round_id}: {limit} attempt(s) used in state {key}",
                    {"state": key, "max_attempts": limit},
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
        raw_output_ref: Optional[str] = None,
    ) -> RoundRecord:
        """Record an attempt result; exhaust retries as soon as the last fails."""
        if outcome not in ("succeeded", "failed"):
            raise InvalidArgumentError("outcome must be 'succeeded' or 'failed'")
        if outcome == "failed" and (not isinstance(error, str) or not error.strip()):
            raise InvalidArgumentError("error is required for a failed attempt")
        if outcome == "succeeded" and error is not None:
            raise InvalidArgumentError("error is only valid for a failed attempt")
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
                raw_output_ref=raw_output_ref,
            )
            record.updated_at = now
            if outcome == "failed" and attempt.number >= record.config.max_attempts_per_step:
                record.error = {
                    "error_category": "retry",
                    "message": f"Step {target.value} failed after {attempt.number} attempt(s): {error}",
                    "retryable": False,
                    "round_id": round_id,
                    "failed_in_state": record.state.value,
                    "details": {"state": target.value, "max_attempts": attempt.number},
                    "occurred_at": now,
                }
                record.outcome = "failed"
                self._append(record, RoundState.FAILED, detail=f"retry: step {target.value} exhausted")
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
                details={"state": record.state.value},
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
        """Close the round as FAILED and store a contract-style error."""
        if category not in ROUND_ERROR_CATEGORIES:
            raise InvalidArgumentError(f"Unknown round error category: {category}")
        self._validate_json(details or {}, "error details")
        with self._lock:
            record = self._load_open(round_id)
            failed_in = record.state.value
            record.error = {
                "error_category": category,
                "message": message,
                "retryable": retryable,
                "round_id": round_id,
                "failed_in_state": failed_in,
                "details": details or {},
                "occurred_at": self._now(record.transitions[-1].at if record.transitions else None),
            }
            record.outcome = "failed"
            self._append(record, RoundState.FAILED, detail=f"{category}: {message}")
            self._store.save(record)
            return self._load(round_id)

    def mark_inconclusive(
        self, round_id: str, reason: str, *, details: Optional[Dict[str, Any]] = None
    ) -> RoundRecord:
        """Close the round as INCONCLUSIVE (e.g. evidence missing or incomplete)."""
        if not isinstance(reason, str) or not reason.strip():
            raise InvalidArgumentError("reason must be a non-empty string")
        self._validate_json(details or {}, "inconclusive details")
        with self._lock:
            record = self._load_open(round_id)
            record.outcome = "inconclusive"
            record.error = {
                "error_category": "validation",
                "message": reason,
                "retryable": False,
                "round_id": round_id,
                "failed_in_state": record.state.value,
                "details": details or {},
                "occurred_at": self._now(record.transitions[-1].at if record.transitions else None),
            }
            self._append(record, RoundState.INCONCLUSIVE, detail=reason)
            self._store.save(record)
            return self._load(round_id)

    def complete(
        self, round_id: str, judge_decision: str, feedback_ref: str
    ) -> RoundRecord:
        """Step 8: close the round after the feedback record is stored.

        The decision is whatever the judge returned; this method only records
        it. A judge ``inconclusive`` closes the round as INCONCLUSIVE.
        """
        if judge_decision not in VALID_JUDGE_DECISIONS:
            raise InvalidArgumentError(
                f"judge_decision must be one of {VALID_JUDGE_DECISIONS}, got {judge_decision!r}"
            )
        if not feedback_ref:
            raise InvalidArgumentError("feedback_ref is required to close a round")
        with self._lock:
            record = self._load_open(round_id)
            if record.state is not RoundState.JUDGED:
                raise InvalidTransitionError(
                    f"Round can only be completed from judged, not {record.state.value}"
                )
            target = (
                RoundState.INCONCLUSIVE
                if judge_decision == "inconclusive"
                else RoundState.COMPLETED
            )
            record.outcome = judge_decision
            if judge_decision == "inconclusive":
                record.error = {
                    "error_category": "validation",
                    "message": "Judge returned an inconclusive result",
                    "retryable": False,
                    "round_id": round_id,
                    "failed_in_state": record.state.value,
                    "details": {"judge_decision": judge_decision},
                    "occurred_at": self._now(record.transitions[-1].at),
                }
            self._append(
                record,
                target,
                detail=f"judge decision: {judge_decision}",
                artifact_name="feedback_record",
                artifact_ref=feedback_ref,
            )
            self._store.save(record)
            return self._load(round_id)

    # ----------------------------------------------------------------- auditing
    def verify_integrity(self, round_id: str) -> None:
        """Raise IntegrityError if the persisted round record is inconsistent."""
        record = self._load(round_id)
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
            if (t.artifact_name is None) != (t.artifact_ref is None):
                raise IntegrityError(f"Round {round_id}: incomplete artifact at sequence {t.sequence}")
            if t.artifact_name is not None:
                expected_artifacts[t.artifact_name] = t.artifact_ref
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
            if not isinstance(record.error, dict) or record.error.get("round_id") != round_id:
                raise IntegrityError(f"Round {round_id}: invalid error record")
            parse_timestamp(record.error.get("occurred_at"), "error.occurred_at")

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
        """Return the stored error for a failed/inconclusive round, else None.

        Shape is provisional until the shared ``error_response`` contract is
        agreed; align the field names with that contract when it lands.
        """
        return self._load(round_id).error
