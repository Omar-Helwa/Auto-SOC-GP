"""Adapt the real Red component to the shared component-service boundary.

This wraps ``RedRole`` from 02_red_role as a ``ServiceResult`` producer;
``WorkflowComponentAdapter`` exposes its proposal through the Orchestrator's
``red.run`` protocol. The workflow and caller do not depend on the Red model
gateway implementation.

Note on packaging: 02_red_role is not an importable package name (leading
digit), so this adapter places its root first on sys.path to import its public
entry point (``interfaces.red_role``). The Orchestrator uses the distinct
``orchestrator_interfaces`` namespace to avoid shadowing Red's ``interfaces``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from shared_services.controller.services import CallableService, ServiceResult

REPO_ROOT = Path(__file__).resolve().parents[2]
RED_ROOT = REPO_ROOT / "02_red_role"
RED_MOCK_GATEWAY = RED_ROOT / "dev" / "mocks" / "model_gateway"
ADAPTER_ROOT = Path(__file__).resolve().parent


def _ensure_red_on_path() -> None:
    for p in (RED_ROOT, RED_MOCK_GATEWAY):
        sp = str(p)
        if sp not in sys.path:
            sys.path.insert(0, sp)


def build_red_service(gateway=None, *, provider: str | None = None) -> CallableService:
    """Return a Service backed by the real RedRole.

    ``gateway`` is any ModelGateway. If omitted, the Red component's mock
    gateway is used unless a Platform provider is configured.
    """
    _ensure_red_on_path()
    if str(ADAPTER_ROOT) not in sys.path:
        sys.path.append(str(ADAPTER_ROOT))
    from interfaces.red_role import RedRole  # from 02_red_role

    if gateway is None:
        selected_provider = (
            provider or os.environ.get("AUTOSOC_MODEL_PROVIDER") or ""
        ).strip().lower()
        if selected_provider in ("xai", "grok", "groq"):
            from model_gateway_service import build_platform_gateway, for_red

            gateway = for_red(build_platform_gateway(selected_provider))
        else:
            from mock_gateway import MockModelGateway  # from 02_red_role/dev/mocks

            gateway = MockModelGateway(mode="normal")

    red = RedRole(gateway)

    def handle(payload: dict) -> ServiceResult:
        result = red.run(payload)
        contract = "red_proposal" if "scenario" in result else "error_response"
        return ServiceResult(contract=contract, payload=result)

    return CallableService(handle)
