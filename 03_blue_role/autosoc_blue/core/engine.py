"""BlueEngine: blue_input -> blue_proposal.

validate input -> build context -> proposer -> normalise -> pre-flight
-> (retry once with the failure reasons) -> deterministic fallback
-> validate output -> return.

The engine never runs an attack, never judges and never changes judge criteria:
it only returns a bounded edit proposal, checked locally.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Sequence

from ..ports import EvidenceSource, Proposer, ProposerError, RuleValidator
from ..schemas import validation
from ..schemas.errors import BlueContractError
from ..schemas.models import BlueInput, BlueProposal
from ..schemas.serializer import proposal_to_contract
from .context import BlueContext, build_context
from .draft import Draft
from .errors import InputError, NoProposalError
from .normalise import normalise
from .preflight import PreflightReport, run_preflight


@dataclass
class Attempt:
    proposer: str
    number: int
    status: str  # accepted | rejected | error
    reasons: list[str] = field(default_factory=list)
    edits: list[dict] = field(default_factory=list)
    source: str = ""  # e.g. "llm:claude-sonnet-5-5" or "deterministic"

    def to_dict(self) -> dict:
        return {"proposer": self.proposer, "source": self.source or self.proposer, "attempt": self.number,
                "status": self.status, "reasons": self.reasons, "edits": self.edits}


@dataclass
class BlueResult:
    proposal: dict
    attempts: list[Attempt]
    proposer_used: str
    notes: list[str] = field(default_factory=list)

    def trace(self) -> dict:
        return {"proposer_used": self.proposer_used, "notes": self.notes,
                "attempts": [a.to_dict() for a in self.attempts]}


class BlueEngine:
    def __init__(
        self,
        proposer: Proposer | None = None,
        *,
        fallback: Proposer | None = None,
        validator: RuleValidator | None = None,
        evidence: EvidenceSource | None = None,
        max_attempts: int = 2,
        allow_partial: bool = False,
    ) -> None:
        from ..adapters.deterministic import DeterministicProposer
        from ..adapters.validators import LocalSigmaValidator

        self.proposer = proposer or DeterministicProposer()
        # No point falling back to the same deterministic logic twice.
        self.fallback = fallback if fallback is not None else (
            DeterministicProposer() if self.proposer.name != "deterministic" else None
        )
        self.validator = validator or LocalSigmaValidator()
        self.evidence = evidence
        self.max_attempts = max(1, max_attempts)
        self.allow_partial = allow_partial

    # ------------------------------------------------------------------ #
    def propose(self, blue_input: dict) -> dict:
        """Return a contract-valid blue_proposal, or raise a BlueError."""
        return self.propose_with_trace(blue_input).proposal

    def propose_with_trace(self, blue_input: dict) -> BlueResult:
        inp = self._parse_input(blue_input)
        try:
            ctx = build_context(inp, self.evidence)
        except Exception as exc:  # unparsable rule text
            raise InputError(f"detection.rule_text cannot be used: {exc}") from exc

        attempts: list[Attempt] = []
        plan: list[tuple[Proposer, int]] = []
        tries = self.max_attempts if self.proposer.uses_feedback else 1
        plan += [(self.proposer, n) for n in range(1, tries + 1)]
        if self.fallback is not None:
            plan.append((self.fallback, 1))

        feedback: list[str] = []
        for proposer, number in plan:
            fb = feedback if (number > 1 and proposer.uses_feedback) else []
            proposal = self._attempt(proposer, number, ctx, fb, attempts)
            if proposal is not None:
                return BlueResult(proposal, attempts, attempts[-1].source or proposer.name, list(ctx.notes))
            if attempts[-1].reasons and proposer is self.proposer:
                feedback = attempts[-1].reasons

        last = attempts[-1].reasons if attempts else []
        raise NoProposalError(
            "no edit passed the pre-flight checks; the evidence may not separate the false "
            "positives from the attacks within the allowed edits",
            details={"attempts": [a.to_dict() for a in attempts], "last_reasons": last},
        )

    # ------------------------------------------------------------------ #
    def _parse_input(self, blue_input) -> BlueInput:
        if not isinstance(blue_input, dict):
            raise InputError("blue_input must be a JSON object")
        result = validation.validate_blue_input(blue_input)
        if not result.ok:
            raise InputError(
                f"blue_input is invalid: {result.summary()}",
                category=validation.input_error_category(result),
                details={"errors": [{"path": e.path, "message": e.message} for e in result.errors]},
            )
        return BlueInput.from_dict(blue_input)

    def _attempt(self, proposer: Proposer, number: int, ctx: BlueContext,
                 feedback: Sequence[str], attempts: list[Attempt]) -> dict | None:
        try:
            draft = proposer.propose(ctx, feedback)
        except ProposerError as exc:
            attempts.append(Attempt(proposer.name, number, "error", [f"proposer_error: {exc}"]))
            return None
        except Exception as exc:  # a broken proposer must not take the round down
            attempts.append(Attempt(proposer.name, number, "error", [f"proposer_crash: {type(exc).__name__}: {exc}"]))
            return None

        draft = normalise(draft, ctx)
        report = run_preflight(ctx, draft, self.validator, allow_partial=self.allow_partial)
        edits = [e.to_dict() for e in draft.edits]
        if not report.ok:
            attempts.append(Attempt(proposer.name, number, "rejected", report.reasons(), edits, draft.source))
            return None
        try:
            proposal = self._assemble(ctx.input, draft, report)
        except BlueContractError as exc:
            attempts.append(Attempt(proposer.name, number, "rejected", [f"schema: {exc}"], edits, draft.source))
            return None
        attempts.append(Attempt(proposer.name, number, "accepted", [i.message for i in report.issues], edits, draft.source))
        return proposal

    def _assemble(self, inp: BlueInput, draft: Draft, report: PreflightReport) -> dict:
        addressed = list(draft.addressed_false_positives)
        if report.preview_verified:
            addressed = [e for e in addressed if e in report.removed_false_positives]
        fps = {fp.evidence_id: fp for fp in inp.false_positives}
        rationale = draft.rationale
        left = [e for e in fps if e not in addressed]
        if left:
            note = f"Partial: not addressed {left}."
            rationale = f"{rationale} {note}".strip() if rationale else note
        removed = len(addressed)
        effect = draft.expected_effect or (
            f"Should stop {removed} reviewed false positive(s); the {len(inp.must_detect)} "
            "must-detect case(s) should still match (local check only, the judge measures)."
        )
        justification = draft.justification or (
            f"The edits remove {removed} false positive(s) and a local check shows every "
            "must-detect case still matches."
        )
        proposal = BlueProposal(
            proposal_id=str(uuid.uuid4()),
            task_id=inp.task_id,
            prompt_version=inp.prompt_version,
            detection_id=inp.detection.detection_id,
            rule_version=inp.detection.rule_version,
            edits=draft.edits,
            addressed_false_positives=addressed,
            justification=justification,
            expected_effect=effect,
            evidence_references=[fps[e].evidence_reference for e in addressed],
            rationale=rationale,
        )
        return proposal_to_contract(proposal)
