from __future__ import annotations

import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from openai import APIConnectionError, APITimeoutError

from model_gateway.factory import GatewayConfigError, build_gateway
from model_gateway.gateway import (
    GroqModelGateway,
    ModelGatewayTimeout,
    ModelGatewayUnavailable,
    XaiModelGateway,
)


class ModelGatewayTests(unittest.TestCase):
    def test_xai_gateway_uses_json_mode_and_returns_model_metadata(self) -> None:
        seen = {}

        class Responses:
            def create(self, **kwargs):
                seen.update(kwargs)
                return SimpleNamespace(
                    id="response-1",
                    model="grok-4.7",
                    created_at=1795560000,
                    output_text='{"edits": []}',
                    usage=SimpleNamespace(input_tokens=21, output_tokens=8),
                )

        gateway = XaiModelGateway(
            api_key="test-key",
            model="grok-4.7",
            client=SimpleNamespace(responses=Responses()),
        )
        response = gateway.generate("system prompt", "task prompt")

        self.assertEqual(seen["model"], "grok-4.7")
        self.assertEqual(seen["input"][0], {"role": "system", "content": "system prompt"})
        self.assertEqual(seen["input"][1], {"role": "user", "content": "task prompt"})
        self.assertEqual(seen["text"], {"format": {"type": "json_object"}})
        self.assertFalse(seen["store"])
        self.assertEqual(response.model_id, "grok-4.7")
        self.assertEqual(response.meta["provider"], "xai")
        self.assertEqual(response.meta["provider_response_id"], "response-1")
        self.assertEqual(response.meta["input_tokens"], 21)
        self.assertEqual(response.meta["output_tokens"], 8)
        self.assertTrue(response.meta["generated_at"].endswith("+00:00"))
        expected_ref = "sha256:" + hashlib.sha256(response.text.encode()).hexdigest()
        self.assertEqual(response.meta["raw_output_ref"], expected_ref)

    def test_request_parameters_cannot_override_platform_model_controls(self) -> None:
        seen = {}

        class Responses:
            def create(self, **kwargs):
                seen.update(kwargs)
                return SimpleNamespace(
                    output_text="{}",
                    usage=None,
                )

        gateway = XaiModelGateway(
            api_key="test-key",
            model="grok-4.7",
            client=SimpleNamespace(responses=Responses()),
        )
        gateway.generate(
            "system",
            "task",
            {
                "model": "unapproved-model",
                "store": True,
                "text": {"format": {"type": "text"}},
            },
        )

        self.assertEqual(seen["model"], "grok-4.7")
        self.assertFalse(seen["store"])
        self.assertEqual(seen["text"], {"format": {"type": "json_object"}})

    def test_empty_provider_configuration_does_not_create_a_gateway(self) -> None:
        self.assertIsNone(build_gateway("none"))

    def test_xai_provider_requires_an_api_key(self) -> None:
        with patch("model_gateway.factory.load_dotenv"), patch.dict(
            "os.environ", {}, clear=True
        ):
            with self.assertRaisesRegex(GatewayConfigError, "XAI_API_KEY"):
                build_gateway("xai")

    def test_xai_provider_does_not_use_groq_key_alias(self) -> None:
        with patch("model_gateway.factory.load_dotenv"), patch.dict(
            "os.environ", {"XAI_KEY": "test-key"}, clear=True
        ):
            with self.assertRaisesRegex(GatewayConfigError, "XAI_API_KEY"):
                build_gateway("xai")

    def test_groq_provider_accepts_legacy_xai_key_variable(self) -> None:
        with patch("model_gateway.factory.load_dotenv"), patch.dict(
            "os.environ", {"XAI_KEY": "test-key"}, clear=True
        ), patch("model_gateway.factory.GroqModelGateway") as gateway_class:
            result = build_gateway("groq")

        self.assertIs(result, gateway_class.return_value)
        gateway_class.assert_called_once_with(api_key="test-key")

    def test_groq_provider_accepts_groq_key_variable(self) -> None:
        with patch("model_gateway.factory.load_dotenv"), patch.dict(
            "os.environ", {"GROQ_KEY": "test-key"}, clear=True
        ), patch("model_gateway.factory.GroqModelGateway") as gateway_class:
            result = build_gateway("groq")

        self.assertIs(result, gateway_class.return_value)
        gateway_class.assert_called_once_with(api_key="test-key")

    def test_groq_gateway_uses_groq_responses_api_and_metadata(self) -> None:
        seen = {}

        class Responses:
            def create(self, **kwargs):
                seen.update(kwargs)
                return SimpleNamespace(
                    id="groq-response-1",
                    model="openai/gpt-oss-20b",
                    created_at=1795560000,
                    output_text='{"ok": true}',
                    usage=SimpleNamespace(input_tokens=12, output_tokens=4),
                )

        gateway = GroqModelGateway(
            api_key="test-key",
            client=SimpleNamespace(responses=Responses()),
        )
        response = gateway.generate("system prompt", "task prompt")

        self.assertEqual(gateway.BASE_URL, "https://api.groq.com/openai/v1")
        self.assertEqual(seen["model"], "openai/gpt-oss-20b")
        self.assertEqual(seen["text"], {"format": {"type": "json_object"}})
        self.assertFalse(seen["store"])
        self.assertEqual(response.meta["provider"], "groq")
        self.assertEqual(response.meta["provider_response_id"], "groq-response-1")
        self.assertEqual(response.meta["input_tokens"], 12)
        self.assertEqual(response.meta["output_tokens"], 4)

    def test_empty_model_response_is_explicitly_rejected(self) -> None:
        class Responses:
            def create(self, **kwargs):
                return SimpleNamespace(
                    output_text=None
                )

        gateway = XaiModelGateway(
            api_key="test-key",
            client=SimpleNamespace(responses=Responses()),
        )
        with self.assertRaisesRegex(ModelGatewayUnavailable, "empty or malformed"):
            gateway.generate("system", "task")

    def test_timeout_is_mapped_and_unexpected_provider_errors_are_not_hidden(self) -> None:
        class Responses:
            def create(self, **kwargs):
                request = httpx.Request("POST", XaiModelGateway.BASE_URL)
                raise APITimeoutError(request=request)

        gateway = XaiModelGateway(
            api_key="test-key",
            client=SimpleNamespace(responses=Responses()),
        )
        with self.assertRaises(ModelGatewayTimeout):
            gateway.generate("system", "task")

        class UnexpectedResponses:
            def create(self, **kwargs):
                raise RuntimeError("unexpected test error")

        gateway = XaiModelGateway(
            api_key="test-key",
            client=SimpleNamespace(responses=UnexpectedResponses()),
        )
        with self.assertRaisesRegex(RuntimeError, "unexpected test error"):
            gateway.generate("system", "task")

    def test_connection_failure_is_mapped_to_unavailable(self) -> None:
        class Responses:
            def create(self, **kwargs):
                request = httpx.Request("POST", XaiModelGateway.BASE_URL)
                raise APIConnectionError(request=request)

        gateway = XaiModelGateway(
            api_key="test-key",
            client=SimpleNamespace(responses=Responses()),
        )
        with self.assertRaisesRegex(ModelGatewayUnavailable, "xAI model request failed"):
            gateway.generate("system", "task")


if __name__ == "__main__":
    unittest.main()
