"""Small, dependency-free client for Splunk's search export REST endpoint."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPSHandler, Request, build_opener
from uuid import uuid4

from validation.evidence import validate_evidence


class SplunkError(RuntimeError):
    """Raised when Splunk rejects a request or returns an invalid response."""


class SplunkApprovalError(SplunkError):
    """Raised when an operation is not approved by the configured authority."""


class SplunkExecutionError(SplunkError):
    """Raised for a failed execution, retaining its failure record."""

    def __init__(self, message: str, execution: "SplunkExecutionRecord") -> None:
        super().__init__(message)
        self.execution = execution

    def as_dict(self) -> dict[str, Any]:
        return {"execution": self.execution.as_dict()}


@dataclass(frozen=True)
class SplunkConfig:
    base_url: str
    username: str
    password: str
    app: str = "search"
    owner: str = "nobody"
    verify_tls: bool = True
    ca_cert: str | None = None
    allow_insecure_http: bool = False
    timeout_seconds: float = 30.0
    max_events: int = 1000

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("base_url must be an absolute http(s) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base_url must not contain credentials")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("base_url must contain only the Splunk server origin")
        if parsed.scheme == "http" and not self.allow_insecure_http:
            raise ValueError("HTTP requires allow_insecure_http=True for isolated local use")
        if not self.username or not self.password:
            raise ValueError("username and password must not be empty")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", self.app):
            raise ValueError("app must be a valid Splunk application name")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", self.owner):
            raise ValueError("owner must be a valid Splunk namespace owner")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        if self.max_events <= 0:
            raise ValueError("max_events must be greater than zero")
        if not self.verify_tls and self.ca_cert:
            raise ValueError("ca_cert cannot be used when verify_tls is disabled")


@dataclass(frozen=True)
class ApprovedSearchRequest:
    task_id: str
    task_version: str
    operation_id: str
    approval_id: str
    spl: str
    earliest_time: str = "-15m"
    latest_time: str = "now"

    def __post_init__(self) -> None:
        for name in ("task_id", "task_version", "operation_id", "approval_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"{name} must be a non-empty string of at most 256 characters")
        if not isinstance(self.spl, str) or not self.spl.strip():
            raise ValueError("spl must be a non-empty string")
        if len(self.spl) > 100_000:
            raise ValueError("spl exceeds the 100000 character limit")
        for name in ("earliest_time", "latest_time"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > 128:
                raise ValueError(f"{name} must be a non-empty string of at most 128 characters")


class OperationAuthorizer(Protocol):
    """Boundary to the trusted validator/approval service."""

    def is_approved(self, request: ApprovedSearchRequest) -> bool:
        ...


@dataclass(frozen=True)
class TelemetryEvidence:
    event_id: str
    timestamp: str
    fields: Mapping[str, Any]
    host: str | None = None
    source: str | None = None
    sourcetype: str | None = None
    raw: str | None = None

    def as_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "fields": dict(self.fields),
        }
        for key in ("host", "source", "sourcetype", "raw"):
            value = getattr(self, key)
            if value is not None:
                record[key] = value
        return record


@dataclass(frozen=True)
class SearchResult:
    events: tuple[TelemetryEvidence, ...]
    truncated: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "events": [event.as_dict() for event in self.events],
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class SplunkExecutionRecord:
    execution_id: str
    task_id: str
    task_version: str
    operation_id: str
    approval_id: str
    status: str
    started_at: str
    completed_at: str
    event_count: int
    truncated: bool
    failure_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "execution_id": self.execution_id,
            "task_id": self.task_id,
            "task_version": self.task_version,
            "operation_id": self.operation_id,
            "approval_id": self.approval_id,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "event_count": self.event_count,
            "truncated": self.truncated,
        }
        if self.failure_reason is not None:
            record["failure_reason"] = self.failure_reason
        return record


@dataclass(frozen=True)
class SplunkExecutionResult:
    execution: SplunkExecutionRecord
    search_result: SearchResult

    def as_dict(self) -> dict[str, Any]:
        return {
            "execution": self.execution.as_dict(),
            "search_result": self.search_result.as_dict(),
        }


class SplunkClient:
    """Executes only approved, bounded searches and records each execution."""

    def __init__(self, config: SplunkConfig, authorizer: OperationAuthorizer) -> None:
        if authorizer is None or not callable(getattr(authorizer, "is_approved", None)):
            raise ValueError("an operation authorizer is required")
        self._config = config
        self._authorizer = authorizer
        if config.verify_tls:
            context = ssl.create_default_context(cafile=config.ca_cert)
        else:
            context = ssl._create_unverified_context()
        self._opener = build_opener(HTTPSHandler(context=context))
        self._endpoint = (
            f"{config.base_url.rstrip('/')}/servicesNS/"
            f"{quote(config.owner, safe='')}/{quote(config.app, safe='')}"
            "/search/jobs/export"
        )

    def execute(self, operation: ApprovedSearchRequest) -> SplunkExecutionResult:
        if not isinstance(operation, ApprovedSearchRequest):
            raise ValueError("operation must be an ApprovedSearchRequest")
        if not self._authorizer.is_approved(operation):
            raise SplunkApprovalError(
                f"Splunk operation {operation.operation_id!r} is not approved"
            )

        execution_id = str(uuid4())
        started_at = _utc_now()
        try:
            result = self._search(
                operation.spl,
                earliest_time=operation.earliest_time,
                latest_time=operation.latest_time,
            )
        except SplunkError as exc:
            record = SplunkExecutionRecord(
                execution_id=execution_id,
                task_id=operation.task_id,
                task_version=operation.task_version,
                operation_id=operation.operation_id,
                approval_id=operation.approval_id,
                status="failed",
                started_at=started_at,
                completed_at=_utc_now(),
                event_count=0,
                truncated=False,
                failure_reason=str(exc),
            )
            raise SplunkExecutionError(str(exc), record) from exc

        record = SplunkExecutionRecord(
            execution_id=execution_id,
            task_id=operation.task_id,
            task_version=operation.task_version,
            operation_id=operation.operation_id,
            approval_id=operation.approval_id,
            status="succeeded",
            started_at=started_at,
            completed_at=_utc_now(),
            event_count=len(result.events),
            truncated=result.truncated,
        )
        return SplunkExecutionResult(execution=record, search_result=result)

    def _search(
        self,
        spl: str,
        *,
        earliest_time: str,
        latest_time: str,
    ) -> SearchResult:

        payload = urlencode(
            {
                "search": spl.strip(),
                "earliest_time": earliest_time,
                "latest_time": latest_time,
                "max_count": str(self._config.max_events + 1),
                "output_mode": "json",
            }
        ).encode("utf-8")
        credentials = base64.b64encode(
            f"{self._config.username}:{self._config.password}".encode("utf-8")
        ).decode("ascii")
        request = Request(
            self._endpoint,
            data=payload,
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )

        events: list[TelemetryEvidence] = []
        truncated = False
        try:
            with self._opener.open(
                request, timeout=self._config.timeout_seconds
            ) as response:
                for line_number, raw_line in enumerate(response, start=1):
                    try:
                        line = raw_line.decode("utf-8").strip()
                    except UnicodeDecodeError as exc:
                        raise SplunkError(
                            f"Splunk returned invalid UTF-8 on response line {line_number}"
                        ) from exc
                    if not line:
                        continue
                    try:
                        message = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise SplunkError(
                            f"Splunk returned invalid JSON on response line {line_number}"
                        ) from exc
                    if not isinstance(message, dict):
                        raise SplunkError(
                            f"Splunk returned an unexpected response on line {line_number}"
                        )

                    messages = message.get("messages", [])
                    if messages:
                        failures = [
                            item.get("text", "Splunk search failed")
                            for item in messages
                            if isinstance(item, dict)
                            and str(item.get("type", "")).upper()
                            in ("ERROR", "FATAL")
                        ]
                        if failures:
                            raise SplunkError("; ".join(str(item) for item in failures))

                    record = message.get("result")
                    if record is None:
                        continue
                    if not isinstance(record, dict):
                        raise SplunkError("Splunk returned a non-object search result")
                    if len(events) == self._config.max_events:
                        truncated = True
                        break
                    events.append(self._to_evidence(record))
        except HTTPError as exc:
            exc.close()
            raise SplunkError(f"Splunk returned HTTP {exc.code}") from exc
        except URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise SplunkError("Splunk request timed out") from exc
            raise SplunkError(f"Could not connect to Splunk: {exc.reason}") from exc
        except TimeoutError as exc:
            raise SplunkError("Splunk request timed out") from exc
        except OSError as exc:
            raise SplunkError(f"Splunk transport failed: {exc}") from exc

        return SearchResult(events=tuple(events), truncated=truncated)

    @staticmethod
    def _to_evidence(record: Mapping[str, Any]) -> TelemetryEvidence:
        timestamp = record.get("_time", record.get("timestamp"))
        if timestamp is None or isinstance(timestamp, (dict, list)):
            raise SplunkError("Splunk event is missing a scalar _time value")
        timestamp_text = str(timestamp)

        event_id = record.get("event_id", record.get("_cd"))
        if event_id is None:
            encoded = json.dumps(
                record, sort_keys=True, separators=(",", ":"), default=str
            ).encode("utf-8")
            event_id = hashlib.sha256(encoded).hexdigest()

        fields = {
            key: value
            for key, value in record.items()
            if key
            not in {
                "_time",
                "timestamp",
                "event_id",
                "_cd",
                "_raw",
                "host",
                "source",
                "sourcetype",
            }
        }
        evidence = TelemetryEvidence(
            event_id=str(event_id),
            timestamp=timestamp_text,
            fields=fields,
            host=_optional_text(record.get("host")),
            source=_optional_text(record.get("source")),
            sourcetype=_optional_text(record.get("sourcetype")),
            raw=_optional_text(record.get("_raw")),
        )
        try:
            validate_evidence(evidence.as_dict())
        except ValueError as exc:
            raise SplunkError(f"Splunk event failed evidence validation: {exc}") from exc
        return evidence


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        raise SplunkError("Splunk event metadata fields must be scalar values")
    return str(value)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
