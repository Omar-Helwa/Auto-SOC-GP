"""Adapt the real Blue component to the controller's Service interface.

Same shape as ``red_service.py``: ``registry.register("blue", build_blue_service())``
plugs the real Blue component (03_blue_role, package ``autosoc_blue``) into a round.

Two things live here because the controller cannot supply them yet:

1. ``build_blue_service`` wraps ``BlueRole.run`` as a Service. Blue's output is a
   ``blue_proposal``, or an ``error_response`` (the controller then stops the round).
2. The default controller step for "blue" passes only ``{"task_id": ...}``, but Blue
   needs a full ``blue_input`` (rule text, reviewed false positives and must-detect
   events, edit constraints). ``blue_input_from_context`` builds it from the round
   context. Until the platform evidence store exists, the reviewed events come from a
   fixture (``03_blue_role/dev/fixtures/inputs``). ``blue_round_steps`` returns the
   controller's default steps with only the blue step replaced, so no shared code
   changes.

Packaging: ``autosoc_blue`` is a normal installable package (``pip install -e
03_blue_role``). If it is not installed, this adapter appends ``03_blue_role`` to the END
of ``sys.path`` (never the front: 02_red_role also has top-level ``schemas/``).
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from shared_services.controller.round_controller import RoundStep, default_round_steps
from shared_services.controller.services import CallableService, ServiceResult

REPO_ROOT = Path(__file__).resolve().parents[2]
BLUE_ROOT = REPO_ROOT / "03_blue_role"
DEFAULT_EVIDENCE_FIXTURE = BLUE_ROOT / "dev" / "fixtures" / "inputs" / "single_fp.json"
BLUE_PROMPT_VERSION = "blue-system@0.1.0"


def _ensure_blue_importable() -> None:
    try:
        import autosoc_blue  # noqa: F401
    except ImportError:
        sp = str(BLUE_ROOT)
        if sp not in sys.path:
            sys.path.append(sp)


def build_blue_service(engine=None, *, provider: str | None = None) -> CallableService:
    """Return a Service backed by the real BlueRole.

    ``engine`` is any BlueEngine. If omitted, one is built from the environment
    (``BLUE_MODEL_PROVIDER``; default = deterministic proposer, no AI needed).
    """
    _ensure_blue_importable()
    from autosoc_blue import BlueRole, build_engine

    blue = BlueRole(engine or build_engine(provider))

    def handle(payload: dict) -> ServiceResult:
        result = blue.run(payload)
        contract = "blue_proposal" if "edits" in result else "error_response"
        return ServiceResult(contract=contract, payload=result)

    return CallableService(handle)


def blue_input_from_context(ctx: dict, evidence_fixture: Path | str = DEFAULT_EVIDENCE_FIXTURE) -> dict:
    """Build a blue_input from the round context (round_request + reviewed evidence)."""
    rr = ctx.get("round_request", {})
    base = json.loads(Path(evidence_fixture).read_text(encoding="utf-8"))
    blue_input = copy.deepcopy(base)
    blue_input["task_id"] = ctx.get("task_id") or rr.get("task_id") or base["task_id"]
    blue_input["prompt_version"] = rr.get("blue_prompt_version", BLUE_PROMPT_VERSION)
    detection = rr.get("detection", {})
    # The rule text and the reviewed events come from the fixture; ids/versions from the round.
    for key in ("detection_id", "rule_version", "logic_summary"):
        if detection.get(key):
            blue_input["detection"][key] = detection[key]
    return blue_input


def blue_round_steps(evidence_fixture: Path | str = DEFAULT_EVIDENCE_FIXTURE) -> list[RoundStep]:
    """The controller's default steps, with the blue step building a real blue_input."""
    steps = default_round_steps()
    for i, step in enumerate(steps):
        if step.role == "blue":
            steps[i] = RoundStep(
                "blue",
                lambda ctx, _f=evidence_fixture: blue_input_from_context(ctx, _f),
                "Blue proposes a rule edit (real blue_input)",
            )
    return steps
