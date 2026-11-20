"""Round lifecycle management for the AutoSOC orchestrator."""

from .errors import (
    ConcurrencyError,
    IntegrityError,
    InvalidArgumentError,
    InvalidRoundRequestError,
    InvalidTransitionError,
    ROUND_ERROR_CATEGORIES,
    RetryExhaustedError,
    RoundClosedError,
    RoundManagementError,
    RoundNotFoundError,
    RoundTimedOutError,
)
from .manager import RoundManager
from .models import AttemptRecord, REQUIRED_VERSION_KEYS, RoundConfig, RoundRecord, Transition
from .states import (
    ALLOWED_TRANSITIONS,
    FORWARD_PATH,
    TERMINAL_STATES,
    RoundState,
    is_terminal,
    next_forward_state,
)
from .store import InMemoryRoundStore, JsonFileRoundStore, RoundStore

__all__ = [
    "ALLOWED_TRANSITIONS",
    "FORWARD_PATH",
    "TERMINAL_STATES",
    "REQUIRED_VERSION_KEYS",
    "ConcurrencyError",
    "AttemptRecord",
    "InMemoryRoundStore",
    "IntegrityError",
    "InvalidArgumentError",
    "InvalidRoundRequestError",
    "InvalidTransitionError",
    "JsonFileRoundStore",
    "RetryExhaustedError",
    "ROUND_ERROR_CATEGORIES",
    "RoundClosedError",
    "RoundConfig",
    "RoundManagementError",
    "RoundManager",
    "RoundNotFoundError",
    "RoundTimedOutError",
    "RoundRecord",
    "RoundState",
    "RoundStore",
    "Transition",
    "is_terminal",
    "next_forward_state",
]
