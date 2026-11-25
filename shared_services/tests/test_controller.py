"""Tests for the shared controller facade and component service adapters."""

from __future__ import annotations

import pytest

from shared_services.controller import round_controller
from shared_services.controller.round_controller import RoundController
from shared_services.controller.services import (
    CallableService,
    ServiceAdapterError,
    ServiceResult,
    WorkflowComponentAdapter,
)


def test_round_controller_delegates_run_and_resume(repo, monkeypatch):
    request = {"task_id": "controller-facade-test"}
    services = object()
    validator = object()
    run_result = object()
    resume_result = object()
    calls = []

    class Workflow:
        def run_round(self, value):
            calls.append(("run_round", value))
            return run_result

        def run_open_round(self, round_id):
            calls.append(("run_open_round", round_id))
            return resume_result

    monkeypatch.setattr(
        round_controller,
        "_create_workflow",
        lambda repository, supplied_services, supplied_validator: (
            calls.append(("factory", repository, supplied_services, supplied_validator))
            or Workflow()
        ),
    )
    controller = RoundController(repo, services, validator=validator)

    assert controller.run_round(request) is run_result
    assert controller.run_open_round(request["task_id"]) is resume_result
    assert calls == [
        ("factory", repo, services, validator),
        ("run_round", request),
        ("run_open_round", request["task_id"]),
    ]


def test_workflow_component_adapter_returns_expected_contract_payload():
    payload = {"contract_version": "0.1.0", "proposal_id": "proposal-1"}
    service = CallableService(lambda _request: ServiceResult("red_proposal", payload))

    result = WorkflowComponentAdapter(service, "red_proposal").run({"task_id": "task-1"})

    assert result is payload


def test_workflow_component_adapter_surfaces_retryable_service_errors():
    error = {
        "category": "timeout",
        "message": "model gateway timed out",
        "retryable": True,
    }
    service = CallableService(lambda _request: ServiceResult("error_response", error))

    with pytest.raises(ServiceAdapterError) as raised:
        WorkflowComponentAdapter(service, "red_proposal").run({"task_id": "task-1"})
    assert raised.value.category == "timeout"
    assert raised.value.retryable is True
    assert raised.value.details == error
