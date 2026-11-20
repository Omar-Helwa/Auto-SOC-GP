"""Typed local models for the blue contracts.

Dataclasses for the ``blue_input`` Blue receives and the ``blue_proposal`` it
emits. They parse from / serialize to the contract dict shape but do NOT
enforce the contract: that is the schema's job (see ``validation.py``).
``to_dict`` omits unset optional fields so output stays contract-valid
(``additionalProperties: false`` rejects stray keys).
"""

from __future__ import annotations

from dataclasses import dataclass, field


def _put(out: dict, key: str, value) -> None:
    if value is not None:
        out[key] = value


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
        return cls(d["evidence_id"], d["evidence_type"], d.get("provenance_ref"))

    def to_dict(self) -> dict:
        out = {"evidence_id": self.evidence_id, "evidence_type": self.evidence_type}
        _put(out, "provenance_ref", self.provenance_ref)
        return out


@dataclass
class ObservedCase:
    """A reviewed event: a false positive, or an attack that must stay detected."""

    evidence_reference: EvidenceReference
    observed_fields: dict[str, str]
    label_note: str | None = None

    @property
    def evidence_id(self) -> str:
        return self.evidence_reference.evidence_id

    @classmethod
    def from_dict(cls, d: dict) -> "ObservedCase":
        return cls(
            EvidenceReference.from_dict(d["evidence_reference"]),
            dict(d["observed_fields"]),
            d.get("label_note"),
        )


# --------------------------------------------------------------------------- #
# blue_input
# --------------------------------------------------------------------------- #
@dataclass
class Detection:
    detection_id: str
    rule_version: str
    rule_format: str
    rule_text: str
    logic_summary: str
    attack_techniques: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "Detection":
        return cls(
            d["detection_id"], d["rule_version"], d["rule_format"], d["rule_text"],
            d["logic_summary"], list(d.get("attack_techniques", [])),
        )


@dataclass
class EditConstraints:
    allowed_operations: list[str]
    allowed_fields: list[str]
    max_edits: int
    attacker_controllable_fields: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "EditConstraints":
        return cls(
            list(d["allowed_operations"]), list(d["allowed_fields"]), int(d["max_edits"]),
            list(d.get("attacker_controllable_fields", [])),
        )


@dataclass
class PriorBlueEdit:
    proposal_id: str
    decision: str
    summary: str
    failure_reason: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "PriorBlueEdit":
        return cls(d["proposal_id"], d["decision"], d["summary"], d.get("failure_reason"))


@dataclass
class BlueInput:
    contract_version: str
    task_id: str
    prompt_version: str
    output_contract_version: str
    detection: Detection
    false_positives: list[ObservedCase]
    must_detect: list[ObservedCase]
    edit_constraints: EditConstraints
    prior_blue_edits: list[PriorBlueEdit] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "BlueInput":
        return cls(
            contract_version=d["contract_version"],
            task_id=d["task_id"],
            prompt_version=d["prompt_version"],
            output_contract_version=d["output_contract_version"],
            detection=Detection.from_dict(d["detection"]),
            false_positives=[ObservedCase.from_dict(c) for c in d["false_positives"]],
            must_detect=[ObservedCase.from_dict(c) for c in d["must_detect"]],
            edit_constraints=EditConstraints.from_dict(d["edit_constraints"]),
            prior_blue_edits=[PriorBlueEdit.from_dict(p) for p in d.get("prior_blue_edits", [])],
        )


# --------------------------------------------------------------------------- #
# blue_proposal
# --------------------------------------------------------------------------- #
@dataclass
class FieldCondition:
    field: str
    modifier: str
    values: list[str]

    @classmethod
    def from_dict(cls, d: dict) -> "FieldCondition":
        return cls(d["field"], d["modifier"], list(d["values"]))

    def to_dict(self) -> dict:
        return {"field": self.field, "modifier": self.modifier, "values": list(self.values)}


@dataclass
class RuleEdit:
    operation: str
    conditions: list[FieldCondition]
    reason: str
    target_selection: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "RuleEdit":
        return cls(
            d["operation"], [FieldCondition.from_dict(c) for c in d["conditions"]],
            d["reason"], d.get("target_selection"),
        )

    def to_dict(self) -> dict:
        out: dict = {"operation": self.operation}
        _put(out, "target_selection", self.target_selection)
        out["conditions"] = [c.to_dict() for c in self.conditions]
        out["reason"] = self.reason
        return out


@dataclass
class ReferenceRule:
    rule_id: str
    title: str
    source: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "ReferenceRule":
        return cls(d["rule_id"], d["title"], d.get("source"))

    def to_dict(self) -> dict:
        out = {"rule_id": self.rule_id, "title": self.title}
        _put(out, "source", self.source)
        return out


@dataclass
class BlueProposal:
    proposal_id: str
    task_id: str
    prompt_version: str
    detection_id: str
    rule_version: str
    edits: list[RuleEdit]
    addressed_false_positives: list[str]
    justification: str
    expected_effect: str | None = None
    reference_rules: list[ReferenceRule] = field(default_factory=list)
    evidence_references: list[EvidenceReference] = field(default_factory=list)
    rationale: str | None = None
    contract_version: str = "0.1.0"

    @classmethod
    def from_dict(cls, d: dict) -> "BlueProposal":
        dut = d["detection_under_test"]
        return cls(
            proposal_id=d["proposal_id"],
            task_id=d["task_id"],
            prompt_version=d["prompt_version"],
            detection_id=dut["detection_id"],
            rule_version=dut["rule_version"],
            edits=[RuleEdit.from_dict(e) for e in d["edits"]],
            addressed_false_positives=list(d["addressed_false_positives"]),
            justification=d["justification"],
            expected_effect=d.get("expected_effect"),
            reference_rules=[ReferenceRule.from_dict(r) for r in d.get("reference_rules", [])],
            evidence_references=[EvidenceReference.from_dict(r) for r in d.get("evidence_references", [])],
            rationale=d.get("rationale"),
            contract_version=d.get("contract_version", "0.1.0"),
        )

    def to_dict(self) -> dict:
        out: dict = {
            "contract_version": self.contract_version,
            "proposal_id": self.proposal_id,
            "task_id": self.task_id,
            "prompt_version": self.prompt_version,
            "detection_under_test": {"detection_id": self.detection_id, "rule_version": self.rule_version},
            "edits": [e.to_dict() for e in self.edits],
            "addressed_false_positives": list(self.addressed_false_positives),
            "justification": self.justification,
        }
        _put(out, "expected_effect", self.expected_effect)
        if self.reference_rules:
            out["reference_rules"] = [r.to_dict() for r in self.reference_rules]
        if self.evidence_references:
            out["evidence_references"] = [r.to_dict() for r in self.evidence_references]
        # Blue structurally has no execution / judging capability: always acknowledged.
        out["constraints_ack"] = {
            "within_allowed_edits": True,
            "no_execution": True,
            "no_verdict": True,
            "no_judge_criteria_change": True,
        }
        _put(out, "rationale", self.rationale)
        return out
