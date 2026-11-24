"""Ports: the interfaces the Blue core depends on.

The core never imports a concrete model SDK, evidence store or rule engine.
Adapters implement these protocols and are injected, so a mock (dev) and a real
service (integration) are interchangeable by configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Mapping, Protocol, Sequence, runtime_checkable

if TYPE_CHECKING:  # pragma: no cover
    from .core.context import BlueContext
    from .core.draft import Draft


# --------------------------------------------------------------------------- #
# Model gateway (same shape as the Red role's gateway)
# --------------------------------------------------------------------------- #
@dataclass
class ModelResponse:
    text: str
    model_id: str = "unknown"
    meta: dict = field(default_factory=dict)


class ModelTimeout(Exception):
    """The model did not answer within the time budget."""


class ModelUnavailable(Exception):
    """The model service could not be reached or is not configured."""


@runtime_checkable
class ModelGateway(Protocol):
    def generate(self, system: str, task: str, params: dict | None = None) -> ModelResponse:
        """Return the raw model answer, or raise ModelTimeout / ModelUnavailable."""
        ...


# --------------------------------------------------------------------------- #
# Evidence source (optional): more fields for a case, fetched by reference
# --------------------------------------------------------------------------- #
@runtime_checkable
class EvidenceSource(Protocol):
    def fetch(self, evidence_id: str) -> Mapping[str, str] | None:
        """Extra observed fields for an evidence id, or None if unknown.

        Only fields missing from the input are added. Values are untrusted log
        text, exactly like the ones in the input.
        """
        ...


# --------------------------------------------------------------------------- #
# Rule validator: does a rule parse, and does it match an event?
# --------------------------------------------------------------------------- #
class RuleUnverifiable(Exception):
    """The validator cannot decide (unsupported rule feature). Never treated as a pass."""


@runtime_checkable
class RuleValidator(Protocol):
    def check(self, rule_text: str) -> list[str]:
        """Structural problems of the rule (empty list = fine)."""
        ...

    def matches(self, rule_text: str, event: Mapping[str, str]) -> bool:
        """True if the rule matches the event. Raise RuleUnverifiable if it cannot tell."""
        ...


# --------------------------------------------------------------------------- #
# Proposer: the thing that suggests edits
# --------------------------------------------------------------------------- #
class ProposerError(Exception):
    """The proposer could not produce a usable draft (bad model output, no safe edit, ...)."""


@runtime_checkable
class Proposer(Protocol):
    name: str
    uses_feedback: bool  # True if a retry with pre-flight reasons can change the answer

    def propose(self, ctx: "BlueContext", feedback: Sequence[str] = ()) -> "Draft":
        ...
