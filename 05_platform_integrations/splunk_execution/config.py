"""Load the Splunk connection and fixed search scope from the repository .env."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from math import isfinite
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv

from .client import OperationAuthorizer, SplunkClient, SplunkConfig

REPO_ROOT = Path(__file__).resolve().parents[2]
_INDEX_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_SOURCETYPE_NAME = re.compile(r"^[A-Za-z0-9_.:/-]{1,256}$")


@dataclass(frozen=True)
class SplunkRuntimeConfig:
    connection: SplunkConfig
    index: str
    sourcetype: str | None

    @property
    def scoped_search(self) -> str:
        terms = [f"index={self.index}"]
        if self.sourcetype:
            escaped = self.sourcetype.replace("\\", "\\\\").replace('"', '\\"')
            terms.append(f'sourcetype="{escaped}"')
        return "search " + " ".join(terms)


def load_splunk_runtime_config(
    env_file: str | Path | None = None,
) -> SplunkRuntimeConfig:
    """Load Splunk credentials and a non-wildcard index scope without logging them."""
    load_dotenv(env_file or REPO_ROOT / ".env", override=False)

    base_url = _required("AUTOSOC_SPLUNK_URL").strip()
    parsed_url = urlsplit(base_url)
    if parsed_url.port == 8000:
        raise ValueError(
            "AUTOSOC_SPLUNK_URL must use Splunk's management API port "
            "(normally 8089), not the Splunk Web port 8000"
        )

    index = _required("AUTOSOC_SPLUNK_INDEX").strip()
    if not _INDEX_NAME.fullmatch(index):
        raise ValueError("AUTOSOC_SPLUNK_INDEX must be one literal index name")

    sourcetype = os.environ.get("AUTOSOC_SPLUNK_SOURCETYPE") or None
    if sourcetype is not None:
        sourcetype = sourcetype.strip()
        if not sourcetype or not _SOURCETYPE_NAME.fullmatch(sourcetype):
            raise ValueError(
                "AUTOSOC_SPLUNK_SOURCETYPE contains unsupported characters"
            )

    connection = SplunkConfig(
        base_url=base_url,
        username=_required("AUTOSOC_SPLUNK_USERNAME").strip(),
        password=_required("AUTOSOC_SPLUNK_PASSWORD"),
        app=os.environ.get("AUTOSOC_SPLUNK_APP", "search").strip() or "search",
        owner=os.environ.get("AUTOSOC_SPLUNK_OWNER", "nobody").strip() or "nobody",
        verify_tls=_boolean("AUTOSOC_SPLUNK_VERIFY_TLS", default=True),
        ca_cert=os.environ.get("AUTOSOC_SPLUNK_CA_CERT") or None,
        allow_insecure_http=_boolean(
            "AUTOSOC_SPLUNK_ALLOW_INSECURE_HTTP", default=False
        ),
        timeout_seconds=_positive_float(
            "AUTOSOC_SPLUNK_TIMEOUT_SECONDS", default=30.0
        ),
        max_events=_positive_int("AUTOSOC_SPLUNK_MAX_EVENTS", default=1000),
    )
    return SplunkRuntimeConfig(connection, index, sourcetype)


def build_splunk_client_from_env(
    authorizer: OperationAuthorizer,
) -> SplunkClient:
    """Construct a client from .env while requiring an explicit approval boundary."""
    runtime = load_splunk_runtime_config()
    return SplunkClient(runtime.connection, authorizer)


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value or not value.strip():
        raise ValueError(f"{name} must be set in the environment or repository .env")
    return value


def _boolean(name: str, *, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{name} must be a boolean value")


def _positive_float(name: str, *, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not isfinite(parsed) or parsed <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return parsed


def _positive_int(name: str, *, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return parsed
