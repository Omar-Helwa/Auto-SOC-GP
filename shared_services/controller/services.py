"""Adapters for component clients consumed by the Orchestrator workflow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol, runtime_checkable


@dataclass(frozen=True)
class ServiceResult:
    """A component adapter response tagged with its shared contract name."""

    contract: str
    payload: dict[str, Any]


@runtime_checkable
class Service(Protocol):
    def handle(self, payload: dict[str, Any]) -> ServiceResult: ...


class ServiceAdapterError(RuntimeError):
    """A service-boundary response the Orchestrator cannot accept."""

    def __init__(
        self,
        message: str,
        *,
        category: str = "internal",
        retryable: bool = False,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.retryable = retryable
        self.details = dict(details or {})


class CallableService:
    """Adapt a function returning ``ServiceResult`` to the component boundary."""

    def __init__(self, fn: Callable[[dict[str, Any]], ServiceResult]) -> None:
        self._fn = fn

    def handle(self, payload: dict[str, Any]) -> ServiceResult:
        return self._fn(payload)


class WorkflowComponentAdapter:
    """Translate a contract-tagged component client into the workflow ``run`` API."""

    def __init__(self, service: Service, expected_contract: str) -> None:
        self._service = service
        self._expected_contract = expected_contract

    def run(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        result = self._service.handle(dict(payload))
        if not isinstance(result, ServiceResult):
            raise ServiceAdapterError("Component adapter did not return ServiceResult")
        if result.contract == "error_response":
            error = result.payload
            category = error.get("category")
            if category not in {
                "validation",
                "missing_information",
                "dependency",
                "timeout",
                "internal",
            }:
                category = "internal"
            raise ServiceAdapterError(
                str(error.get("message") or "Component returned error_response"),
                category=category,
                retryable=error.get("retryable") is True,
                details=error,
            )
        if result.contract != self._expected_contract:
            raise ServiceAdapterError(
                f"Expected {self._expected_contract!r}, received {result.contract!r}",
                category="validation",
                details={"expected_contract": self._expected_contract, "actual_contract": result.contract},
            )
        return result.payload
