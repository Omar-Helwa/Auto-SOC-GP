"""Build a ready-to-use BlueEngine from configuration."""

from __future__ import annotations

import os

from .adapters.deterministic import DeterministicProposer
from .adapters.gateways.factory import build_gateway
from .adapters.llm import LLMProposer
from .core.engine import BlueEngine


def build_engine(provider: str | None = None, *, gateway=None, allow_partial: bool | None = None,
                 evidence=None) -> BlueEngine:
    """Engine from env/arguments.

    - no provider (default): deterministic proposer only, no AI.
    - mock / anthropic / openai: LLM proposer, with the deterministic proposer as fallback.
    ``gateway`` overrides the provider (inject any ModelGateway).
    """
    if allow_partial is None:
        allow_partial = os.environ.get("BLUE_ALLOW_PARTIAL", "").lower() in ("1", "true", "yes")
    gateway = gateway if gateway is not None else build_gateway(provider)
    proposer = LLMProposer(gateway) if gateway is not None else DeterministicProposer()
    return BlueEngine(proposer, evidence=evidence, allow_partial=allow_partial)
