"""Adapt the real Red component to the controller's Service interface.

The controller (shared_services) relays to anything implementing
``handle(payload) -> ServiceResult``. This wraps ``RedRole`` from 02_red_role so
``registry.register("red", build_red_service(gateway))`` plugs the real Red
component into a round. Swap the injected gateway (mock now, Member 5's hosted
model later) without touching the controller.

Note on packaging: 02_red_role is not an importable package name (leading
digit), so this adapter puts the component root on sys.path and imports its
public entry (``interfaces.red_role``). When all five components are assembled,
the team should give each a unique import root to avoid clashes between their
identically named internal folders (schemas/, interfaces/, ...). Until then,
import the real Red component through THIS adapter only.
"""

from __future__ import annotations

import sys
from pathlib import Path

from shared_services.controller.services import CallableService, ServiceResult

REPO_ROOT = Path(__file__).resolve().parents[2]
RED_ROOT = REPO_ROOT / "02_red_role"
RED_MOCK_GATEWAY = RED_ROOT / "dev" / "mocks" / "model_gateway"


def _ensure_red_on_path() -> None:
    for p in (RED_ROOT, RED_MOCK_GATEWAY):
        sp = str(p)
        if sp not in sys.path:
            sys.path.insert(0, sp)


def build_red_service(gateway=None) -> CallableService:
    """Return a Service backed by the real RedRole.

    ``gateway`` is any ModelGateway. If omitted, the Red component's mock
    gateway (normal mode) is used so the pipeline runs with no hosted model.
    """
    _ensure_red_on_path()
    from interfaces.red_role import RedRole  # from 02_red_role

    if gateway is None:
        from mock_gateway import MockModelGateway  # from 02_red_role/dev/mocks
        gateway = MockModelGateway(mode="normal")

    red = RedRole(gateway)

    def handle(payload: dict) -> ServiceResult:
        result = red.run(payload)
        contract = "red_proposal" if "scenario" in result else "error_response"
        return ServiceResult(contract=contract, payload=result)

    return CallableService(handle)
