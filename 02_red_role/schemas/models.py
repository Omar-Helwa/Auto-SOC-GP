"""B1 + B2 — typed local models for the red contracts.

These dataclasses are the Red component's in-memory representation of the
``red_input`` it receives and the ``red_proposal`` it emits. They know how to
parse from / serialize to the contract dict shape, but they do NOT enforce the
contract themselves — validation is the schema's job (see ``validation.py``).
Keeping the two concerns separate means the schema stays the source of truth.

``to_dict`` omits optional fields that are unset so the output stays clean and
contract-valid (``additionalProperties: false`` rejects stray keys).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import constants


# --------------------------------------------------------------------------- #
# Shared sub-objects
# --------------------------------------------------------------------------- #
@dataclass
class EvidenceReference:
    evidence_id: str
    evidence_type: str
    provenance_ref: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceReference":
        return cls(
            evidence_id=d["evidence_id"],
            evidence_type=d["evidence_type"],
            provenance_ref=d.get("provenance_ref"),
        )

    def to_dict(self) -> dict:
        out = {"evidence_id": self.evidence_id, "evidence_type": self.evidence_type}
        if self.provenance_ref is not None:
            out["provenance_ref"] = self.provenance_ref
        return out


@dataclass
class DetectionUnderTest:
    detection_id: str
    rule_version: str

    @classmethod
    def from_dict(cls, d: dict) -> "DetectionUnderTest":
        return cls(detection_id=d["detection_id"], rule_version=d["rule_version"])

    def to_dict(self) -> dict:
        return {"detection_id": self.detection_id, "rule_version": self.rule_version}


# --------------------------------------------------------------------------- #
# red_proposal (B1)
# --------------------------------------------------------------------------- #
@dataclass
class WorkflowStep:
    action: str
    target: str
    benign_context: str
    parameters: dict | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "WorkflowStep":
        return cls(
            action=d["action"],
            target=d["target"],
            benign_context=d["benign_context"],
            parameters=d.get("parameters"),
        )

    def to_dict(self) -> dict:
        out = {
            "action": self.action,
            "target": self.target,
            "benign_context": self.benign_context,
        }
        if self.parameters is not None:
            out["parameters"] = self.parameters
        return out


@dataclass
class Scenario:
    family: str
    title: str
    description: str
    workflow_steps: list[WorkflowStep] = field(default_factory=list)
    expected_signal: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "Scenario":
        return cls(
            family=d["family"],
            title=d["title"],
            description=d["description"],
            workflow_steps=[WorkflowStep.from_dict(s) for s in d.get("workflow_steps", [])],
            expected_signal=d.get("expected_signal"),
        )

    def to_dict(self) -> dict:
        out = {
            "family": self.family,
            "title": self.title,
            "description": self.description,
            "workflow_steps": [s.to_dict() for s in self.workflow_steps],
        }
        if self.expected_signal is not None:
            out["expected_signal"] = self.expected_signal
        return out


@dataclass
class ConstraintsAck:
    within_allowed_families: bool = True
    no_execution: bool = True
    no_verdict: bool = True

    @classmethod
    def from_dict(cls, d: dict) -> "ConstraintsAck":
        return cls(
            within_allowed_families=d.get("within_allowed_families", True),
            no_execution=d.get("no_execution", True),
            no_verdict=d.get("no_verdict", True),
        )

    def to_dict(self) -> dict:
        return {
            "within_allowed_families": self.within_allowed_families,
            "no_execution": self.no_execution,
            "no_verdict": self.no_verdict,
        }


@dataclass
class RedProposal:
    proposal_id: str
    task_id: str
    prompt_version: str
    detection_under_test: DetectionUnderTest
    scenario: Scenario
    benign_justification: str
    contract_version: str = constants.RED_PROPOSAL_VERSION
    evidence_references: list[EvidenceReference] = field(default_factory=list)
    constraints_ack: ConstraintsAck = field(default_factory=ConstraintsAck)
    rationale: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "RedProposal":
        return cls(
            contract_version=d.get("contract_version", constants.RED_PROPOSAL_VERSION),
            proposal_id=d["proposal_id"],
            task_id=d["task_id"],
            prompt_version=d["prompt_version"],
            detection_under_test=DetectionUnderTest.from_dict(d["detection_under_test"]),
            scenario=Scenario.from_dict(d["scenario"]),
            benign_justification=d["benign_justification"],
            evidence_references=[
                EvidenceReference.from_dict(e) for e in d.get("evidence_references", [])
            ],
            constraints_ack=ConstraintsAck.from_dict(d.get("constraints_ack", {})),
            rationale=d.get("rationale"),
        )

    def to_dict(self) -> dict:
        out = {
            "contract_version": self.contract_version,
            "proposal_id": self.proposal_id,
            "task_id": self.task_id,
            "prompt_version": self.prompt_version,
            "detection_under_test": self.detection_under_test.to_dict(),
            "scenario": self.scenario.to_dict(),
            "benign_justification": self.benign_justification,
            "constraints_ack": self.constraints_ack.to_dict(),
        }
        if self.evidence_references:
            out["evidence_references"] = [e.to_dict() for e in self.evidence_references]
        if self.rationale is not None:
            out["rationale"] = self.rationale
        return out


# --------------------------------------------------------------------------- #
# red_input (B2)
# --------------------------------------------------------------------------- #
@dataclass
class Detection:
    detection_id: str
    rule_version: str
    logic_summary: str
    description: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "Detection":
        return cls(
            detection_id=d["detection_id"],
            rule_version=d["rule_version"],
            logic_summary=d["logic_summary"],
            description=d.get("description"),
        )

    def to_dict(self) -> dict:
        out = {
            "detection_id": self.detection_id,
            "rule_version": self.rule_version,
            "logic_summary": self.logic_summary,
        }
        if self.description is not None:
            out["description"] = self.description
        return out


@dataclass
class BenignConstraints:
    allowed_scenario_families: list[str] = field(default_factory=list)
    max_workflow_steps: int = constants.MAX_WORKFLOW_STEPS
    allowed_actions: list[str] = field(default_factory=list)
    forbidden_notes: list[str] | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "BenignConstraints":
        return cls(
            allowed_scenario_families=list(d.get("allowed_scenario_families", [])),
            max_workflow_steps=d.get("max_workflow_steps", constants.MAX_WORKFLOW_STEPS),
            allowed_actions=list(d.get("allowed_actions", [])),
            forbidden_notes=d.get("forbidden_notes"),
        )

    def to_dict(self) -> dict:
        out = {
            "allowed_scenario_families": self.allowed_scenario_families,
            "max_workflow_steps": self.max_workflow_steps,
            "allowed_actions": self.allowed_actions,
        }
        if self.forbidden_notes is not None:
            out["forbidden_notes"] = self.forbidden_notes
        return out


@dataclass
class RedInput:
    task_id: str
    detection: Detection
    benign_constraints: BenignConstraints
    prompt_version: str
    contract_version: str = constants.RED_INPUT_VERSION
    output_contract_version: str = constants.RED_PROPOSAL_VERSION
    permitted_evidence_refs: list[EvidenceReference] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "RedInput":
        return cls(
            contract_version=d.get("contract_version", constants.RED_INPUT_VERSION),
            task_id=d["task_id"],
            detection=Detection.from_dict(d["detection"]),
            benign_constraints=BenignConstraints.from_dict(d["benign_constraints"]),
            prompt_version=d["prompt_version"],
            output_contract_version=d.get(
                "output_contract_version", constants.RED_PROPOSAL_VERSION
            ),
            permitted_evidence_refs=[
                EvidenceReference.from_dict(e)
                for e in d.get("permitted_evidence_refs", [])
            ],
        )

    def to_dict(self) -> dict:
        out = {
            "contract_version": self.contract_version,
            "task_id": self.task_id,
            "detection": self.detection.to_dict(),
            "benign_constraints": self.benign_constraints.to_dict(),
            "prompt_version": self.prompt_version,
            "output_contract_version": self.output_contract_version,
        }
        if self.permitted_evidence_refs:
            out["permitted_evidence_refs"] = [
                e.to_dict() for e in self.permitted_evidence_refs
            ]
        return out
