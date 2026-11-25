"""Shared model gateway contract and xAI Grok adapter."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable


class ModelGatewayTimeout(TimeoutError):
    """The hosted model did not respond within the configured time budget."""


class ModelGatewayUnavailable(RuntimeError):
    """The hosted model could not be reached or returned an unusable response."""


@dataclass(frozen=True)
class ModelResponse:
    text: str
    model_id: str
    meta: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class ModelGateway(Protocol):
    def generate(
        self, system: str, task: str, params: dict[str, Any] | None = None
    ) -> ModelResponse:
        """Return raw model text and metadata, or raise a gateway error."""
        ...


class OpenAIResponsesGateway:
    """Shared implementation for OpenAI-compatible Responses API providers."""

    BASE_URL = ""
    DEFAULT_MODEL = ""
    MODEL_ENV = ""
    API_KEY_ENV_VARS: tuple[str, ...] = ()
    API_KEY_ENV_DESCRIPTION = ""
    PROVIDER = ""
    PROVIDER_LABEL = ""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
        client: Any = None,
    ) -> None:
        self.api_key = api_key or next(
            (
                os.environ[name]
                for name in self.API_KEY_ENV_VARS
                if os.environ.get(name)
            ),
            None,
        )
        self.model = model or os.environ.get(self.MODEL_ENV) or self.DEFAULT_MODEL
        self.timeout = (
            timeout
            if timeout is not None
            else float(os.environ.get("AUTOSOC_MODEL_TIMEOUT_SECONDS", "60"))
        )
        self.max_retries = (
            max_retries
            if max_retries is not None
            else int(os.environ.get("AUTOSOC_MODEL_MAX_RETRIES", "2"))
        )
        if self.timeout <= 0:
            raise ValueError("model gateway timeout must be greater than zero")
        if self.max_retries < 0:
            raise ValueError("model gateway max retries cannot be negative")
        self._client = client

    def _get_client(self):
        if self._client is None:
            if not self.api_key:
                raise ModelGatewayUnavailable(f"{self.API_KEY_ENV_DESCRIPTION} is not set")
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise ModelGatewayUnavailable(
                    "the 'openai' package is not installed; install "
                    "05_platform_integrations/requirements.txt"
                ) from exc
            self._client = OpenAI(
                api_key=self.api_key,
                base_url=self.BASE_URL,
                timeout=self.timeout,
                max_retries=self.max_retries,
            )
        return self._client

    def generate(
        self, system: str, task: str, params: dict[str, Any] | None = None
    ) -> ModelResponse:
        client = self._get_client()
        request = {
            "model": self.model,
            "input": [
                {"role": "system", "content": system},
                {"role": "user", "content": task},
            ],
            "text": {"format": {"type": "json_object"}},
            "store": False,
        }
        request.update(params or {})
        request["model"] = self.model
        request["text"] = {"format": {"type": "json_object"}}
        request["store"] = False

        try:
            response = client.responses.create(**request)
        except Exception as exc:
            try:
                from openai import APIError, APITimeoutError
            except ImportError:
                raise
            if isinstance(exc, APITimeoutError):
                raise ModelGatewayTimeout(
                    f"{self.PROVIDER_LABEL} model request timed out "
                    f"after {self.timeout:g} seconds"
                ) from exc
            if isinstance(exc, APIError):
                status_code = getattr(exc, "status_code", None)
                detail = f"HTTP {status_code}" if status_code else type(exc).__name__
                raise ModelGatewayUnavailable(
                    f"{self.PROVIDER_LABEL} model request failed ({detail})"
                ) from exc
            raise

        text = getattr(response, "output_text", None)
        if not isinstance(text, str) or not text.strip():
            raise ModelGatewayUnavailable(
                f"{self.PROVIDER_LABEL} returned an empty or malformed response"
            )

        returned_model = getattr(response, "model", None) or self.model
        usage = getattr(response, "usage", None)
        created = getattr(response, "created_at", None)
        generated_at = (
            datetime.fromtimestamp(created, timezone.utc).isoformat()
            if isinstance(created, (int, float))
            else datetime.now(timezone.utc).isoformat()
        )
        raw_output_ref = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
        meta = {
            "provider": self.PROVIDER,
            "requested_model_id": self.model,
            "model_id": returned_model,
            "generated_at": generated_at,
            "raw_output_ref": raw_output_ref,
            "provider_response_id": getattr(response, "id", None),
            "input_tokens": getattr(usage, "input_tokens", None),
            "output_tokens": getattr(usage, "output_tokens", None),
        }
        return ModelResponse(text=text, model_id=returned_model, meta=meta)


class XaiModelGateway(OpenAIResponsesGateway):
    """Grok gateway using xAI's OpenAI-compatible Responses API."""

    BASE_URL = "https://api.x.ai/v1"
    DEFAULT_MODEL = "grok-4.7"
    MODEL_ENV = "AUTOSOC_MODEL_ID"
    API_KEY_ENV_VARS = ("XAI_API_KEY",)
    API_KEY_ENV_DESCRIPTION = "XAI_API_KEY"
    PROVIDER = "xai"
    PROVIDER_LABEL = "xAI"


class GroqModelGateway(OpenAIResponsesGateway):
    """Gateway for Groq-hosted models using Groq's Responses API."""

    BASE_URL = "https://api.groq.com/openai/v1"
    DEFAULT_MODEL = "openai/gpt-oss-20b"
    MODEL_ENV = "GROQ_MODEL_ID"
    API_KEY_ENV_VARS = ("GROQ_API_KEY", "GROQ_KEY", "XAI_KEY")
    API_KEY_ENV_DESCRIPTION = "GROQ_API_KEY, GROQ_KEY, or legacy XAI_KEY"
    PROVIDER = "groq"
    PROVIDER_LABEL = "Groq"
