"""BlueRole: the boundary the orchestrator calls.

``run(blue_input) -> dict`` has the same signature as the orchestrator's
``MockBlueRole``. It returns a contract-valid ``blue_proposal``, or a
contract-valid ``error_response`` if no safe proposal can be made.
"""

from __future__ import annotations

import os

from .core.engine import BlueEngine
from .core.errors import BlueError
from .factory import build_engine
from .schemas.errors import BlueContractError
from .schemas.serializer import build_error_response, error_to_contract


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


class BlueRole:
    """``embed_edited_rule`` (or env ``BLUE_EMBED_EDITED_RULE=1``) fills the optional
    ``edited_rule`` field of blue_proposal (in the rule's own format: SPL for SPL input).
    Off by default so consumers still holding an older copy of the schema are unaffected."""

    def __init__(self, engine: BlueEngine | None = None, *, embed_edited_rule: bool | None = None):
        self.engine = engine or build_engine()
        self.embed_edited_rule = _env_flag("BLUE_EMBED_EDITED_RULE") if embed_edited_rule is None else embed_edited_rule
        self.last_edited_rule: dict | None = None  # {"format", "text"} of the last proposal, if renderable

    def run(self, blue_input: dict) -> dict:
        task_id = blue_input.get("task_id") if isinstance(blue_input, dict) else None
        try:
            result = self.engine.propose_with_trace(blue_input)
            self.last_edited_rule = None
            fmt = "spl" if blue_input["detection"]["rule_format"] == "spl" else "sigma"
            try:
                self.last_edited_rule = result.edited_rule(fmt)
            except Exception:
                pass
            if self.embed_edited_rule and self.last_edited_rule is not None:
                return result.proposal_with_edited_rule(fmt)
            return result.proposal
        except BlueError as exc:
            return error_to_contract(build_error_response(
                exc.category, exc.message, task_id=task_id, details=exc.details))
        except BlueContractError as exc:
            return error_to_contract(build_error_response("internal", str(exc), task_id=task_id))
        except Exception as exc:  # never leak a stack trace across the boundary
            return error_to_contract(build_error_response(
                "internal", f"unexpected error: {type(exc).__name__}", task_id=task_id))
