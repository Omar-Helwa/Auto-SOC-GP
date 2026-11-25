"""Bridge the Platform model gateway to component-local gateway ports."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PLATFORM_ROOT = REPO_ROOT / "05_platform_integrations"
if str(PLATFORM_ROOT) not in sys.path:
    sys.path.append(str(PLATFORM_ROOT))


def build_platform_gateway(provider: str | None = None):
    from model_gateway import build_gateway

    gateway = build_gateway(provider)
    if gateway is None:
        raise ValueError("a hosted model provider must be selected for this adapter")
    return gateway


class _ComponentGatewayAdapter:
    def __init__(self, gateway, *, response_type, timeout_type, unavailable_type) -> None:
        self._gateway = gateway
        self._response_type = response_type
        self._timeout_type = timeout_type
        self._unavailable_type = unavailable_type

    def generate(self, system: str, task: str, params: dict | None = None):
        from model_gateway import ModelGatewayTimeout, ModelGatewayUnavailable

        try:
            response = self._gateway.generate(system, task, params)
        except ModelGatewayTimeout as exc:
            raise self._timeout_type(str(exc)) from exc
        except ModelGatewayUnavailable as exc:
            raise self._unavailable_type(str(exc)) from exc
        return self._response_type(response.text, response.model_id, response.meta)


def for_blue(gateway):
    from autosoc_blue.ports import ModelResponse, ModelTimeout, ModelUnavailable

    return _ComponentGatewayAdapter(
        gateway,
        response_type=ModelResponse,
        timeout_type=ModelTimeout,
        unavailable_type=ModelUnavailable,
    )


def for_red(gateway):
    from interfaces.model_gateway import ModelResponse, ModelTimeout, ModelUnavailable

    return _ComponentGatewayAdapter(
        gateway,
        response_type=ModelResponse,
        timeout_type=ModelTimeout,
        unavailable_type=ModelUnavailable,
    )
