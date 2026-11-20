"""RedRole — the Red component's public, callable boundary (Epic G3).

One method, ``run(red_input_dict) -> dict``, returns either a contract-valid
``red_proposal`` or a contract-valid ``error_response``. The full flow:

    input -> validate -> context -> prompt -> model gateway -> parse
          -> per-round bounds -> validate+serialize -> red_proposal

Any failure short-circuits to the appropriate error_response category. A
ModelGateway is injected (mock in dev, real adapter in integration), so the
component runs with no live model, Splunk, orchestrator, blue, or judge.
"""

from __future__ import annotations

from interfaces.inputs.input_adapter import InputError, parse_and_validate_input
from interfaces.model_gateway import (
    ModelGateway,
    ModelTimeout,
    ModelUnavailable,
)
from interfaces.outputs.output_adapter import emit_error, emit_proposal
from interfaces.parser import ParseError, parse_proposal
from prompts import registry
from role_context.builder import build_context
from scenarios.bounds import check_bounds


class RedRole:
    def __init__(self, gateway: ModelGateway, *, model_params: dict | None = None):
        self.gateway = gateway
        self.model_params = model_params or {}

    def run(self, red_input_dict: dict) -> dict:
        task_id = red_input_dict.get("task_id") if isinstance(red_input_dict, dict) else None

        # 1. Validate + parse the input.
        try:
            red_input = parse_and_validate_input(red_input_dict)
        except InputError as exc:
            return emit_error(exc.category, exc.message, task_id=task_id, details=exc.details)

        # 2. Build the red-only context and render the prompt.
        ctx = build_context(red_input)
        try:
            prompt = registry.render(red_input.prompt_version, ctx)
        except registry.UnknownPromptVersion as exc:
            return emit_error("validation", str(exc), task_id=red_input.task_id)

        # 3. Call the model gateway.
        try:
            response = self.gateway.generate(prompt["system"], prompt["task"], self.model_params)
        except ModelTimeout as exc:
            return emit_error("timeout", f"model gateway timed out: {exc}", task_id=red_input.task_id)
        except ModelUnavailable as exc:
            return emit_error("dependency", f"model gateway unavailable: {exc}", task_id=red_input.task_id)

        # 4. Parse the raw response into a proposal.
        try:
            proposal = parse_proposal(response.text, red_input, prompt["version"])
        except ParseError as exc:
            return emit_error("validation", f"could not parse model output: {exc}",
                              task_id=red_input.task_id)

        # 5. Enforce this round's bounds + safety.
        violations = check_bounds(proposal.to_dict(), red_input.to_dict())
        if violations:
            return emit_error(
                "validation",
                "proposal is out of scope: " + "; ".join(str(v) for v in violations),
                task_id=red_input.task_id,
                details={"violations": [v.code for v in violations]},
            )

        # 6. Validate + emit the proposal (or internal error if somehow invalid).
        return emit_proposal(proposal)


def run_red(red_input_dict: dict, gateway: ModelGateway, *, model_params: dict | None = None) -> dict:
    """Convenience one-shot: build a RedRole and run a single input."""
    return RedRole(gateway, model_params=model_params).run(red_input_dict)
