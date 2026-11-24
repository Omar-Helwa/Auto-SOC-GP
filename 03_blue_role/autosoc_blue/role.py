"""BlueRole: the boundary the orchestrator calls.

``run(blue_input) -> dict`` has the same signature as the orchestrator's
``MockBlueRole``. It returns a contract-valid ``blue_proposal``, or a
contract-valid ``error_response`` if no safe proposal can be made.
"""

from __future__ import annotations

from .core.engine import BlueEngine
from .core.errors import BlueError
from .factory import build_engine
from .schemas.errors import BlueContractError
from .schemas.serializer import build_error_response, error_to_contract


class BlueRole:
    def __init__(self, engine: BlueEngine | None = None):
        self.engine = engine or build_engine()
        self.last_edited_rule: dict | None = None  # {"format", "text"} of the last proposal, if renderable

    def run(self, blue_input: dict) -> dict:
        task_id = blue_input.get("task_id") if isinstance(blue_input, dict) else None
        try:
            result = self.engine.propose_with_trace(blue_input)
            self.last_edited_rule = None
            try:  # a side product for callers that want it; never part of the contract object
                fmt = "spl" if blue_input["detection"]["rule_format"] == "spl" else "sigma"
                self.last_edited_rule = result.edited_rule(fmt)
            except Exception:
                pass
            return result.proposal
        except BlueError as exc:
            return error_to_contract(build_error_response(
                exc.category, exc.message, task_id=task_id, details=exc.details))
        except BlueContractError as exc:
            return error_to_contract(build_error_response("internal", str(exc), task_id=task_id))
        except Exception as exc:  # never leak a stack trace across the boundary
            return error_to_contract(build_error_response(
                "internal", f"unexpected error: {type(exc).__name__}", task_id=task_id))
