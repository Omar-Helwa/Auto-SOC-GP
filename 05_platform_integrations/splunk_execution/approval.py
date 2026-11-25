"""Human approval for bounded, index-scoped, read-only Splunk searches."""

from __future__ import annotations

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


class ManualCLIApprovalAuthorizer:
    """Ask an operator to approve the exact search in an interactive CLI."""

    def __init__(
        self,
        allowed_index: str,
        *,
        confirm: Callable[[str], str] | None = None,
        allow_read_only_pipeline: bool = False,
    ) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", allowed_index):
            raise ValueError("allowed_index must be one literal index name")
        self._allowed_index = allowed_index
        self._confirm = confirm
        self._allow_read_only_pipeline = allow_read_only_pipeline

    def is_approved(self, request: ApprovedSearchRequest) -> bool:
        display_values = (
            request.task_id,
            request.task_version,
            request.operation_id,
            request.approval_id,
            request.earliest_time,
            request.latest_time,
        )
        if any(not value.isprintable() for value in display_values):
            return False
        if not self._is_scoped_read_only_search(request.spl):
            return False

        confirmation = (
            f"APPROVE {request.approval_id}"
        )
        prompt = (
            "\nSplunk search approval required\n"
            f"Task: {request.task_id} (version {request.task_version})\n"
            f"Operation: {request.operation_id}\n"
            f"Approval reference: {request.approval_id}\n"
            f"Index scope: {self._allowed_index}\n"
            f"Time range: {request.earliest_time} to {request.latest_time}\n"
            f"SPL: {request.spl}\n"
            f"Type {confirmation!r} to execute this read-only search: "
        )
        if self._confirm is not None:
            return self._confirm(prompt).strip() == confirmation
        if not sys.stdin.isatty():
            return False
        try:
            return input(prompt).strip() == confirmation
        except EOFError:
            return False

    def _is_scoped_read_only_search(self, spl: str) -> bool:
        if any(ord(char) < 32 or ord(char) == 127 for char in spl):
            return False
        if any(char in spl for char in (";", "`")):
            return False
        segments = spl.split("|")
        if len(segments) > 1:
            if not self._allow_read_only_pipeline:
                return False
            for segment in segments[1:]:
                words = segment.strip().split(None, 1)
                if not words or words[0].lower() not in _APPROVED_READ_ONLY_PIPELINES:
                    return False
        initial = _INITIAL_INDEX.match(spl)
        if initial is None or initial.group(1).casefold() != self._allowed_index.casefold():
            return False
        indexes = _INDEX_TOKEN.findall(spl)
        return bool(indexes) and all(
            index.casefold() == self._allowed_index.casefold() for index in indexes
        )
