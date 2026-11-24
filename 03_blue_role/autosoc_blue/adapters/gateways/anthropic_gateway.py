"""Anthropic gateway. The ``anthropic`` package is an optional dependency.

Config (environment only, never in code or files):
  ANTHROPIC_API_KEY      required
  BLUE_MODEL_ID          model id (default ``claude-sonnet-5-5``)
  BLUE_MODEL_TIMEOUT     seconds (default 60)
"""

from __future__ import annotations

import os

from ...ports import ModelResponse, ModelTimeout, ModelUnavailable

DEFAULT_MODEL = "claude-sonnet-5-5"


class AnthropicGateway:
    def __init__(self, model: str | None = None, *, api_key: str | None = None,
                 timeout: float | None = None, max_tokens: int = 2000, client=None):
        self.model = model or os.environ.get("BLUE_MODEL_ID") or DEFAULT_MODEL
        self.timeout = timeout if timeout is not None else float(os.environ.get("BLUE_MODEL_TIMEOUT", "60"))
        self.max_tokens = max_tokens
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = client

    def _get_client(self):
        if self._client is None:
            if not self._api_key:
                raise ModelUnavailable("ANTHROPIC_API_KEY is not set")
            try:
                import anthropic
            except ImportError as exc:
                raise ModelUnavailable(
                    "the 'anthropic' package is not installed (pip install autosoc-blue[anthropic])") from exc
            self._client = anthropic.Anthropic(api_key=self._api_key, timeout=self.timeout, max_retries=1)
        return self._client

    def generate(self, system: str, task: str, params: dict | None = None) -> ModelResponse:
        client = self._get_client()
        kwargs = {"model": self.model, "max_tokens": self.max_tokens, "system": system,
                  "messages": [{"role": "user", "content": task}]}
        kwargs.update(params or {})
        try:
            resp = client.messages.create(**kwargs)
        except Exception as exc:
            name = type(exc).__name__
            if "Timeout" in name:
                raise ModelTimeout(str(exc)) from exc
            raise ModelUnavailable(f"{name}: {exc}") from exc
        blocks = getattr(resp, "content", [])
        text = "".join(getattr(b, "text", "") for b in blocks if getattr(b, "type", "text") == "text")
        usage = getattr(resp, "usage", None)
        meta = {"input_tokens": getattr(usage, "input_tokens", None),
                "output_tokens": getattr(usage, "output_tokens", None)}
        return ModelResponse(text, self.model, meta)
