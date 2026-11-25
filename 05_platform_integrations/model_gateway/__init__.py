"""Shared model gateway adapters owned by Platform."""

from .factory import GatewayConfigError, PROVIDERS, build_gateway
from .gateway import (
    GroqModelGateway,
    ModelGateway,
    ModelGatewayTimeout,
    ModelGatewayUnavailable,
    OpenAIResponsesGateway,
    ModelResponse,
    XaiModelGateway,
)

__all__ = [
    "GatewayConfigError",
    "GroqModelGateway",
    "ModelGateway",
    "ModelGatewayTimeout",
    "ModelGatewayUnavailable",
    "ModelResponse",
    "OpenAIResponsesGateway",
    "PROVIDERS",
    "XaiModelGateway",
    "build_gateway",
]
