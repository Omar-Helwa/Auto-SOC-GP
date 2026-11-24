"""Round state model for Architecture 1.

The forward path mirrors the eight-step round flow:

    1  CREATED              orchestrator opens the round with frozen config
    2  RED_PROPOSED         red role returned one bounded proposal
    3  TELEMETRY_COLLECTED  platform validated + ran the approved lab action
    4  EVIDENCE_VERIFIED    Splunk results and reviewed labels stored as evidence
    5  BLUE_PROPOSED        blue role returned one rule-edit proposal
    6  CANDIDATE_EXECUTED   platform validated, compiled and ran the candidate
    7  JUDGED               deterministic judge returned a result
    8  COMPLETED            feedback record stored, round closed

Any non-terminal state may exit to FAILED or INCONCLUSIVE.

Each state also names the contract messages a round must reference when it
enters that state (``REQUIRED_ARTIFACTS``) and the ones it may reference
(``ALLOWED_ARTIFACTS``).
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, FrozenSet, List, Tuple

from .contracts import (
    BASELINE_MATCH_SET,
    BLUE_PROPOSAL,
    CANDIDATE_MATCH_SET,
    CANDIDATE_RULE,
    FEEDBACK_RECORD,
    JUDGE_RESULT,
    RED_PROPOSAL,
    REVIEWED_LABEL_SET,
    TELEMETRY_EVIDENCE,
)


class RoundState(str, Enum):
    CREATED = "created"
    RED_PROPOSED = "red_proposed"
    TELEMETRY_COLLECTED = "telemetry_collected"
    EVIDENCE_VERIFIED = "evidence_verified"
    BLUE_PROPOSED = "blue_proposed"
    CANDIDATE_EXECUTED = "candidate_executed"
    JUDGED = "judged"
    COMPLETED = "completed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


# The fixed Architecture 1 order. Nothing may be skipped or reordered.
FORWARD_PATH: List[RoundState] = [
    RoundState.CREATED,
    RoundState.RED_PROPOSED,
    RoundState.TELEMETRY_COLLECTED,
    RoundState.EVIDENCE_VERIFIED,
    RoundState.BLUE_PROPOSED,
    RoundState.CANDIDATE_EXECUTED,
    RoundState.JUDGED,
    RoundState.COMPLETED,
]

TERMINAL_STATES: FrozenSet[RoundState] = frozenset(
    {RoundState.COMPLETED, RoundState.FAILED, RoundState.INCONCLUSIVE}
)

# Which workflow step number produces each state (for audit readability).
STEP_NUMBER: Dict[RoundState, int] = {
    RoundState.CREATED: 1,
    RoundState.RED_PROPOSED: 2,
    RoundState.TELEMETRY_COLLECTED: 3,
    RoundState.EVIDENCE_VERIFIED: 4,
    RoundState.BLUE_PROPOSED: 5,
    RoundState.CANDIDATE_EXECUTED: 6,
    RoundState.JUDGED: 7,
    RoundState.COMPLETED: 8,
}

# Contract messages that must be referenced when entering a state.
REQUIRED_ARTIFACTS: Dict[RoundState, Tuple[str, ...]] = {
    RoundState.RED_PROPOSED: (RED_PROPOSAL,),
    RoundState.TELEMETRY_COLLECTED: (),
    RoundState.EVIDENCE_VERIFIED: (TELEMETRY_EVIDENCE,),
    RoundState.BLUE_PROPOSED: (BLUE_PROPOSAL,),
    RoundState.CANDIDATE_EXECUTED: (CANDIDATE_RULE, CANDIDATE_MATCH_SET),
    RoundState.JUDGED: (JUDGE_RESULT,),
    RoundState.COMPLETED: (FEEDBACK_RECORD,),
}

# Optional extras. The baseline match set and the label set may arrive with the
# evidence or with the candidate run; the team has not fixed which (see the
# open points on the shared contracts).
_OPTIONAL_ARTIFACTS: Dict[RoundState, Tuple[str, ...]] = {
    RoundState.EVIDENCE_VERIFIED: (REVIEWED_LABEL_SET, BASELINE_MATCH_SET),
    RoundState.CANDIDATE_EXECUTED: (BASELINE_MATCH_SET,),
    RoundState.INCONCLUSIVE: (FEEDBACK_RECORD,),
}

ALLOWED_ARTIFACTS: Dict[RoundState, FrozenSet[str]] = {
    state: frozenset(REQUIRED_ARTIFACTS.get(state, ()) + _OPTIONAL_ARTIFACTS.get(state, ()))
    for state in RoundState
}


def _build_transitions() -> Dict[RoundState, FrozenSet[RoundState]]:
    table: Dict[RoundState, FrozenSet[RoundState]] = {}
    for current, nxt in zip(FORWARD_PATH, FORWARD_PATH[1:]):
        table[current] = frozenset({nxt, RoundState.FAILED, RoundState.INCONCLUSIVE})
    for terminal in TERMINAL_STATES:
        table[terminal] = frozenset()
    return table


ALLOWED_TRANSITIONS: Dict[RoundState, FrozenSet[RoundState]] = _build_transitions()


def is_terminal(state: RoundState) -> bool:
    return state in TERMINAL_STATES


def next_forward_state(state: RoundState) -> RoundState:
    """Return the next state on the forward path (raises ValueError at the end)."""
    idx = FORWARD_PATH.index(state)
    if idx + 1 >= len(FORWARD_PATH):
        raise ValueError(f"{state.value} has no forward state")
    return FORWARD_PATH[idx + 1]
