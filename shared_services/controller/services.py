"""Service abstraction the controller relays to.

Each service (red, platform, blue, judge, ...) is anything with a
``handle(payload) -> ServiceResult`` method. A ``ServiceResult`` says which
contract the returned payload conforms to, so the controller knows which
collection to store it in and whether it is a normal output or an
``error_response``. Real components and mocks implement the same interface, so
the controller does not change when a mock is swapped for a real service.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol, runtime_checkable


@dataclass
class ServiceResult:
    contract: str   # e.g. "red_proposal" or "error_response"
    payload: dict


@runtime_checkable
class Service(Protocol):
    def handle(self, payload: dict) -> ServiceResult: ...


class ServiceRegistry:
    """Maps a role name (e.g. 'red') to the Service that fulfils it."""

    def __init__(self) -> None:
        self._services: dict[str, Service] = {}

    def register(self, role: str, service: Service) -> None:
        self._services[role] = service

    def get(self, role: str) -> Service:
        if role not in self._services:
            raise KeyError(f"No service registered for role {role!r}")
        return self._services[role]

    def has(self, role: str) -> bool:
        return role in self._services


class CallableService:
    """Adapt a plain function ``fn(payload) -> ServiceResult`` into a Service."""

    def __init__(self, fn: Callable[[dict], ServiceResult]) -> None:
        self._fn = fn

    def handle(self, payload: dict) -> ServiceResult:
        return self._fn(payload)


def static_service(contract: str, payload_or_factory) -> CallableService:
    """Build a mock Service that returns a fixed payload (or a factory result).

    ``payload_or_factory`` may be a dict (returned as-is) or a callable taking
    the incoming payload and returning a dict (so it can thread task_id etc.).
    Useful for standing in for a real service that is not wired yet.
    """

    def fn(payload: dict) -> ServiceResult:
        if callable(payload_or_factory):
            out = payload_or_factory(payload)
        else:
            out = dict(payload_or_factory)
        return ServiceResult(contract=contract, payload=out)

    return CallableService(fn)
