"""RoundController — runs one Architecture 1 round, persisting every message.

The controller is a thin, generic pipeline:

    round_request -> [ for each step: build input -> call service -> store output ]
                  -> feedback_record

Each step names the role to call and how to build that service's input from the
accumulated round context. After a service responds, its output is stored in the
matching contract collection and threaded forward. If a service returns an
``error_response`` (or a role has no service wired), the round stops and is
recorded as ``inconclusive`` rather than producing a false result.

The default step list follows the Architecture 1 sequence (red -> platform
execute -> blue -> platform compile -> judge). Swap in real services via the
ServiceRegistry; the controller itself does not change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from ..datastore.repository import MongoRepository
from .services import ServiceRegistry, ServiceResult

ERROR_CONTRACT = "error_response"


@dataclass
class RoundStep:
    role: str                                   # which service to call
    build_input: Callable[[dict], dict]         # context -> that service's input
    label: str = ""


def _red_input_from_context(ctx: dict) -> dict:
    """Map a contract-valid round_request into a red_input payload.

    Red receives the detection's description, never its executable rule text.
    """
    rr = ctx.get("round_request", {})
    detection = rr.get("detection", {})
    red_input = {
        "contract_version": "0.1.0",
        "task_id": ctx.get("task_id"),
        "detection": {
            key: detection[key]
            for key in ("detection_id", "rule_version", "description", "logic_summary")
            if key in detection
        },
        "benign_constraints": rr.get("benign_constraints", {}),
        "prompt_version": rr.get("versions", {}).get("red_prompt", "red-system@0.1.0"),
        "output_contract_version": "0.1.0",
    }
    if "permitted_evidence_refs" in rr:
        red_input["permitted_evidence_refs"] = rr["permitted_evidence_refs"]
    return red_input


def _passthrough_task(ctx: dict) -> dict:
    return {"task_id": ctx.get("task_id")}


def default_round_steps() -> list[RoundStep]:
    return [
        RoundStep("red", _red_input_from_context, "Red proposes a benign workflow"),
        RoundStep("platform_execute", _passthrough_task, "Platform runs it -> telemetry evidence"),
        RoundStep("platform_labels", _passthrough_task, "Platform supplies reviewed labels"),
        RoundStep("platform_baseline", _passthrough_task, "Platform supplies baseline matches"),
        RoundStep("blue", _passthrough_task, "Blue proposes a rule edit"),
        RoundStep("platform_compile", _passthrough_task, "Platform compiles the candidate"),
        RoundStep("platform_candidate_matches", _passthrough_task, "Platform supplies candidate matches"),
        RoundStep("judge", _passthrough_task, "Judge compares matches"),
    ]


@dataclass
class RoundOutcome:
    task_id: str
    outcome: str                    # completed | inconclusive
    reason: str = ""
    stored: dict = field(default_factory=dict)   # role -> contract stored
    feedback_id: str = ""


class RoundController:
    def __init__(
        self,
        repo: MongoRepository,
        registry: ServiceRegistry,
        steps: list[RoundStep] | None = None,
    ) -> None:
        self.repo = repo
        self.registry = registry
        self.steps = steps if steps is not None else default_round_steps()

    def run_round(self, round_request: dict) -> RoundOutcome:
        task_id = round_request.get("task_id")
        self.repo.save("round_request", round_request)

        ctx: dict = {"task_id": task_id, "round_request": round_request, "results": {}}
        stored: dict[str, str] = {}
        artifact_refs: dict[str, str] = {}
        outcome = "completed"
        reason = ""

        for step in self.steps:
            if not self.registry.has(step.role):
                outcome, reason = "inconclusive", f"no service wired for role '{step.role}'"
                break

            payload = step.build_input(ctx)
            result: ServiceResult = self.registry.get(step.role).handle(payload)

            # Persist the service's output in its contract collection.
            inserted_id = self.repo.save(result.contract, result.payload)
            ctx["results"][step.role] = result
            stored[step.role] = result.contract
            artifact_name = result.contract
            if result.contract == "match_set":
                artifact_name = f"{result.payload['role']}_match_set"
            artifact_refs[artifact_name] = f"mongo://{result.contract}/{inserted_id}"

            if result.contract == ERROR_CONTRACT:
                outcome, reason = "inconclusive", f"role '{step.role}' returned an error_response"
                break

        feedback_id = ""
        if outcome == "completed":
            required_refs = {
                "red_proposal",
                "telemetry_evidence",
                "reviewed_label_set",
                "blue_proposal",
                "candidate_rule",
                "baseline_match_set",
                "candidate_match_set",
                "judge_result",
            }
            missing_refs = sorted(required_refs - set(artifact_refs))
            if missing_refs:
                outcome = "inconclusive"
                reason = f"cannot create feedback_record; missing artifact references: {missing_refs}"
            else:
                judge_result = ctx["results"]["judge"].payload
                versions = dict(round_request["versions"])
                versions.update(
                    {
                        "rule_version": round_request["detection"]["rule_version"],
                        "dataset_version": round_request["dataset"]["dataset_version"],
                        "evaluation_set_id": round_request["dataset"]["evaluation_set_id"],
                        "criteria_version": round_request["criteria"]["criteria_version"],
                    }
                )
                feedback = {
                    "contract_version": "0.1.0",
                    "task_id": task_id,
                    "round_id": task_id,
                    "decision": judge_result["decision"],
                    "artifact_refs": {name: artifact_refs[name] for name in sorted(required_refs)},
                    "versions": versions,
                    "judge_result": judge_result,
                    "recorded_at": datetime.now(timezone.utc).isoformat(),
                }
                feedback_id = self.repo.save("feedback_record", feedback)

        return RoundOutcome(
            task_id=task_id,
            outcome=outcome,
            reason=reason,
            stored=stored,
            feedback_id=feedback_id,
        )
