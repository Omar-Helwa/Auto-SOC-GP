"""Human approval for bounded, index-scoped, read-only Splunk searches."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections.abc import Callable

from .client import ApprovedSearchRequest

_INDEX_TOKEN = re.compile(
    r"(?i)(?:^|\s|\()\s*index\s*=\s*([A-Za-z0-9_.-]+)(?=\s|\)|$)"
)
_INITIAL_INDEX = re.compile(
    r"(?i)^\s*(?:search\s+)?\(*\s*index\s*=\s*([A-Za-z0-9_.-]+)(?=\s|\)|$)"
)
_APPROVED_READ_ONLY_PIPELINES = {"stats", "convert", "search"}
_BOUND_APPROVAL_PREFIX = "apv-"


def is_scoped_read_only_search(
    spl: str, allowed_index: str, *, allow_read_only_pipeline: bool = False
) -> bool:
    """True when ``spl`` starts in, and only references, ``allowed_index``."""
    if any(ord(char) < 32 or ord(char) == 127 for char in spl):
        return False
    if any(char in spl for char in (";", "`")):
        return False
    segments = spl.split("|")
    if len(segments) > 1:
        if not allow_read_only_pipeline:
            return False
        for segment in segments[1:]:
            words = segment.strip().split(None, 1)
            if not words or words[0].lower() not in _APPROVED_READ_ONLY_PIPELINES:
                return False
    initial = _INITIAL_INDEX.match(spl)
    if initial is None or initial.group(1).casefold() != allowed_index.casefold():
        return False
    indexes = _INDEX_TOKEN.findall(spl)
    return bool(indexes) and all(
        index.casefold() == allowed_index.casefold() for index in indexes
    )


def search_approval_binding(request: ApprovedSearchRequest, allowed_index: str) -> dict:
    """Every request property an approval covers, excluding the approval id itself."""
    return {
        "task_id": request.task_id,
        "task_version": request.task_version,
        "operation_id": request.operation_id,
        "proposal_id": request.proposal_id,
        "dataset": dict(request.dataset) if request.dataset is not None else None,
        "index": allowed_index,
        "earliest_time": request.earliest_time,
        "latest_time": request.latest_time,
        "spl_sha256": hashlib.sha256(request.spl.strip().encode("utf-8")).hexdigest(),
    }


def bound_approval_id(request: ApprovedSearchRequest, allowed_index: str) -> str:
    """Derive the approval reference that binds ``request`` to its exact scope.

    Changing the task, proposal, dataset, index scope, time range, operation,
    or SPL produces a different id, so an approval for one search cannot be
    presented for another. The id is a binding, not a secret: an authorizer
    must still obtain the operator's (or approval service's) decision.
    """
    canonical = json.dumps(
        search_approval_binding(request, allowed_index),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return _BOUND_APPROVAL_PREFIX + hashlib.sha256(canonical).hexdigest()


class ManualCLIApprovalAuthorizer:
    """Ask an operator to approve the exact search in an interactive CLI.

    With ``require_binding=True`` the request must name its proposal and the
    full frozen dataset (including the evaluation-set checksum), and its
    ``approval_id`` must equal ``bound_approval_id`` for the request and this
    authorizer's index. Requests altered after the id was derived are refused
    without prompting.
    """

    def __init__(
        self,
        allowed_index: str,
        *,
        confirm: Callable[[str], str] | None = None,
        allow_read_only_pipeline: bool = False,
        require_binding: bool = False,
    ) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", allowed_index):
            raise ValueError("allowed_index must be one literal index name")
        self._allowed_index = allowed_index
        self._confirm = confirm
        self._allow_read_only_pipeline = allow_read_only_pipeline
        self._require_binding = require_binding
        self.last_refusal: str | None = None

    @property
    def allowed_index(self) -> str:
        return self._allowed_index

    @property
    def requires_binding(self) -> bool:
        return self._require_binding

    def is_approved(self, request: ApprovedSearchRequest) -> bool:
        """Return the operator's decision; ``last_refusal`` explains a refusal."""
        self.last_refusal = None
        approved = self._decide(request)
        if not approved and self.last_refusal is None:
            self.last_refusal = "the operator's confirmation did not match"
        return approved

    def _refuse(self, reason: str) -> bool:
        self.last_refusal = reason
        return False

    def _decide(self, request: ApprovedSearchRequest) -> bool:
        display_values = [
            request.task_id,
            request.task_version,
            request.operation_id,
            request.approval_id,
            request.earliest_time,
            request.latest_time,
        ]
        if request.proposal_id is not None:
            display_values.append(request.proposal_id)
        if request.dataset is not None:
            display_values.extend(str(value) for value in request.dataset.values())
        if any(not value.isprintable() for value in display_values):
            return self._refuse("a request value contains non-printable characters")
        if not self._is_scoped_read_only_search(request.spl):
            return self._refuse(
                f"the SPL is not a read-only search scoped to index={self._allowed_index}"
            )
        if self._require_binding:
            if request.proposal_id is None or request.dataset is None:
                return self._refuse("a bound approval needs a proposal and a frozen dataset")
            if not request.dataset.get("evaluation_set_checksum"):
                return self._refuse("a bound approval needs the evaluation_set_checksum")
            if request.approval_id != bound_approval_id(request, self._allowed_index):
                return self._refuse("the approval_id does not match the request's binding")

        confirmation = (
            f"APPROVE {request.approval_id}"
        )
        lines = [
            "",
            "Splunk search approval required",
            f"Task: {request.task_id} (version {request.task_version})",
            f"Operation: {request.operation_id}",
            f"Approval reference: {request.approval_id}",
        ]
        if request.proposal_id is not None:
            lines.append(f"Proposal: {request.proposal_id}")
        if request.dataset is not None:
            lines.append(
                "Dataset: "
                + ", ".join(f"{key}={value}" for key, value in sorted(request.dataset.items()))
            )
        lines.extend(
            [
                f"Index scope: {self._allowed_index}",
                f"Time range: {request.earliest_time} to {request.latest_time}",
                f"SPL: {request.spl}",
                f"Type {confirmation!r} to execute this read-only search: ",
            ]
        )
        prompt = "\n".join(lines)
        if self._confirm is not None:
            return self._confirm(prompt).strip() == confirmation
        if not sys.stdin.isatty():
            reason = (
                "approval needs an interactive terminal, but stdin is not a TTY "
                "(in Git Bash run 'winpty python ...', or use PowerShell/Windows Terminal)"
            )
            print(f"Splunk search {request.operation_id} refused: {reason}", file=sys.stderr)
            return self._refuse(reason)
        try:
            return input(prompt).strip() == confirmation
        except EOFError:
            return self._refuse("input ended before the operator confirmed")

    def _is_scoped_read_only_search(self, spl: str) -> bool:
        return is_scoped_read_only_search(
            spl,
            self._allowed_index,
            allow_read_only_pipeline=self._allow_read_only_pipeline,
        )
