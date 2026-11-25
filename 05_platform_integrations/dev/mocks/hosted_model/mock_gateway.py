"""Controlled hosted-model substitute for Platform integration tests."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from model_gateway.gateway import ModelResponse


class MockModelGateway:
    def __init__(self, response_text: str, *, model_id: str = "mock-model") -> None:
        if not response_text.strip():
            raise ValueError("mock response_text cannot be empty")
        if not model_id.strip():
            raise ValueError("mock model_id cannot be empty")
        self.response_text = response_text
        self.model_id = model_id
        self.calls: list[dict] = []

    def generate(
        self, system: str, task: str, params: dict | None = None
    ) -> ModelResponse:
        self.calls.append({"system": system, "task": task, "params": params})
        digest = hashlib.sha256(self.response_text.encode("utf-8")).hexdigest()
        return ModelResponse(
            text=self.response_text,
            model_id=self.model_id,
            meta={
                "provider": "mock",
                "requested_model_id": self.model_id,
                "model_id": self.model_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "raw_output_ref": f"sha256:{digest}",
                "input_tokens": None,
                "output_tokens": None,
            },
        )
