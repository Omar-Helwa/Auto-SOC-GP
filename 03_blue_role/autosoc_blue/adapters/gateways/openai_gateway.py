"""OpenAI gateway. The ``openai`` package is an optional dependency.

Config (environment only):
  OPENAI_API_KEY         required
  BLUE_MODEL_ID          model id (default ``gpt-4.1``, change it freely)
  BLUE_MODEL_TIMEOUT     seconds (default 60)
"""

from __future__ import annotations

import os

from ...ports import ModelResponse, ModelTimeout, ModelUnavailable

DEFAULT_MODEL = "gpt-4.1"


class OpenAIGateway:
    def __init__(self, model: str | None = None, *, api_key: str | None = None,
                 timeout: float | None = None, client=None):
        self.model = model or os.environ.get("BLUE_MODEL_ID") or DEFAULT_MODEL
        self.timeout = timeout if timeout is not None else float(os.environ.get("BLUE_MODEL_TIMEOUT", "60"))
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self._client = client

    def _get_client(self):
        if self._client is None:
            if not self._api_key:
                raise ModelUnavailable("OPENAI_API_KEY is not set")
            try:
                import openai
            except ImportError as exc:
                raise ModelUnavailable(
                    "the 'openai' package is not installed (pip install autosoc-blue[openai])") from exc
            self._client = openai.OpenAI(api_key=self._api_key, timeout=self.timeout, max_retries=1)
        return self._client

    def generate(self, system: str, task: str, params: dict | None = None) -> ModelResponse:
        client = self._get_client()
        kwargs = {"model": self.model,
                  "messages": [{"role": "system", "content": system}, {"role": "user", "content": task}],
                  "response_format": {"type": "json_object"}}
        kwargs.update(params or {})
        try:
            resp = client.chat.completions.create(**kwargs)
        except Exception as exc:
            name = type(exc).__name__
            if "Timeout" in name:
                raise ModelTimeout(str(exc)) from exc
            raise ModelUnavailable(f"{name}: {exc}") from exc
        text = resp.choices[0].message.content or ""
        usage = getattr(resp, "usage", None)
        meta = {"input_tokens": getattr(usage, "prompt_tokens", None),
                "output_tokens": getattr(usage, "completion_tokens", None)}
        return ModelResponse(text, self.model, meta)
