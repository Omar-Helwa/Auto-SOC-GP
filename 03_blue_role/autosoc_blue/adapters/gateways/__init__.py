"""Model gateways: mock (tests/demo) and real providers (Anthropic, OpenAI)."""

from .factory import PROVIDERS, GatewayConfigError, build_gateway  # noqa: F401
from .mock import MockModelGateway  # noqa: F401
