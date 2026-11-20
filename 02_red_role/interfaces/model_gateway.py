"""Model gateway boundary (Epic F1).

The Red component talks to the model only through this interface, so a mock
(dev) and the real hosted-model adapter (Member 5) are interchangeable by
configuration. The component NEVER imports a concrete gateway; one is injected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class ModelResponse:
    text: str
    model_id: str = "unknown"
    meta: dict = field(default_factory=dict)


class ModelTimeout(Exception):
    """The model did not respond within the red time budget (-> timeout error)."""


class ModelUnavailable(Exception):
    """The model gateway/dependency could not be reached (-> dependency error)."""


@runtime_checkable
class ModelGateway(Protocol):
    def generate(self, system: str, task: str, params: dict | None = None) -> ModelResponse:
        """Return the model's raw response, or raise ModelTimeout/ModelUnavailable."""
        ...
