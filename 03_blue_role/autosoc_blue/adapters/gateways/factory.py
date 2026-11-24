"""Pick a gateway from configuration (environment variables)."""

from __future__ import annotations

import os

from ...ports import ModelGateway

PROVIDERS = ("none", "mock", "anthropic", "openai")


class GatewayConfigError(Exception):
    """The requested provider is unknown or not configured (for example a missing key)."""


def build_gateway(provider: str | None = None) -> ModelGateway | None:
    """Return a gateway for ``provider`` (default: env BLUE_MODEL_PROVIDER, else none).

    ``none`` means no model: the deterministic proposer is used alone.
    """
    provider = (provider or os.environ.get("BLUE_MODEL_PROVIDER") or "none").strip().lower()
    if provider in ("none", "deterministic", ""):
        return None
    if provider == "mock":
        from .mock import MockModelGateway
        return MockModelGateway(mode=os.environ.get("BLUE_MOCK_MODE", "normal"))
    if provider == "anthropic":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise GatewayConfigError("BLUE_MODEL_PROVIDER=anthropic needs the ANTHROPIC_API_KEY environment variable")
        from .anthropic_gateway import AnthropicGateway
        return AnthropicGateway()
    if provider == "openai":
        if not os.environ.get("OPENAI_API_KEY"):
            raise GatewayConfigError("BLUE_MODEL_PROVIDER=openai needs the OPENAI_API_KEY environment variable")
        from .openai_gateway import OpenAIGateway
        return OpenAIGateway()
    raise GatewayConfigError(f"unknown provider {provider!r}; choose from {PROVIDERS}")
