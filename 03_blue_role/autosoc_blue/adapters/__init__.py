"""Adapters: concrete implementations of the ports."""

from .deterministic import DeterministicProposer  # noqa: F401
from .evidence import DictEvidenceSource, NullEvidenceSource  # noqa: F401
from .llm import LLMProposer  # noqa: F401
from .validators import LocalSigmaValidator  # noqa: F401
