"""Build the configured shared model gateway."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

from .gateway import GroqModelGateway, XaiModelGateway

PROVIDERS = ("none", "xai", "grok", "groq")

REPO_ROOT = Path(__file__).resolve().parents[2]


class GatewayConfigError(ValueError):
    """The requested provider is unknown or missing required configuration."""


def build_gateway(provider: str | None = None):
    """Build the configured Platform gateway; no provider means no hosted model."""
    load_dotenv(REPO_ROOT / ".env", override=False)
    selected = (
        provider or os.environ.get("AUTOSOC_MODEL_PROVIDER") or "none"
    ).strip().lower()
    if selected in ("", "none", "deterministic"):
        return None
    if selected in ("xai", "grok"):
        api_key = os.environ.get("XAI_API_KEY")
        if not api_key:
            raise GatewayConfigError(
                f"AUTOSOC_MODEL_PROVIDER={selected} requires XAI_API_KEY"
            )
        try:
            return XaiModelGateway(api_key=api_key)
        except ValueError as exc:
            raise GatewayConfigError(str(exc)) from exc
    if selected == "groq":
        api_key = (
            os.environ.get("GROQ_API_KEY")
            or os.environ.get("GROQ_KEY")
            or os.environ.get("XAI_KEY")
        )
        if not api_key:
            raise GatewayConfigError(
                "AUTOSOC_MODEL_PROVIDER=groq requires GROQ_API_KEY "
                "(or GROQ_KEY)"
            )
        try:
            return GroqModelGateway(api_key=api_key)
        except ValueError as exc:
            raise GatewayConfigError(str(exc)) from exc
    raise GatewayConfigError(
        f"unknown provider {selected!r}; choose from {PROVIDERS}"
    )
