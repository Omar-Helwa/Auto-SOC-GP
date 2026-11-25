"""Real gateways (with fake SDK clients), configuration, packaging rules."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from autosoc_blue import BlueEngine
from autosoc_blue.adapters.gateways import GatewayConfigError, build_gateway
from autosoc_blue.adapters.gateways.anthropic_gateway import AnthropicGateway
from autosoc_blue.adapters.gateways.openai_gateway import OpenAIGateway
from autosoc_blue.adapters.llm import LLMProposer
from autosoc_blue.ports import ModelTimeout, ModelUnavailable
from autosoc_blue.schemas._loader import SCHEMA_FILES

PKG = Path(__file__).resolve().parents[2] / "autosoc_blue"
REPO = PKG.parents[1]


# --------------------------------------------------------------------------- #
# gateways
# --------------------------------------------------------------------------- #
def good_answer(fixture_input):
    from autosoc_blue.adapters.gateways.mock import MockModelGateway
    from autosoc_blue.adapters.llm import LLMProposer as P  # noqa: F401
    from autosoc_blue.core.context import build_context
    from autosoc_blue.prompts import registry
    from autosoc_blue.schemas.models import BlueInput

    ctx = build_context(BlueInput.from_dict(fixture_input("single_fp")))
    prompt = registry.render("blue-system@0.1.0", ctx)
    return MockModelGateway().generate(prompt["system"], prompt["task"]).text


def test_anthropic_gateway_calls_the_messages_api_and_works_in_the_engine(fixture_input):
    seen = {}

    class Messages:
        def create(self, **kw):
            seen.update(kw)
            block = SimpleNamespace(type="text", text=good_answer(fixture_input))
            return SimpleNamespace(content=[block], usage=SimpleNamespace(input_tokens=10, output_tokens=5))

    gw = AnthropicGateway(client=SimpleNamespace(messages=Messages()))
    assert gw.model == "claude-sonnet-5-5"
    result = BlueEngine(LLMProposer(gw)).propose_with_trace(fixture_input("single_fp"))
    assert result.proposer_used == "llm:claude-sonnet-5-5"
    assert seen["model"] == "claude-sonnet-5-5" and seen["system"] and seen["messages"][0]["role"] == "user"


def test_openai_gateway_calls_chat_completions(fixture_input, gateway_env):
    gateway_env.setenv("BLUE_MODEL_ID", "my-model")
    seen = {}

    class Completions:
        def create(self, **kw):
            seen.update(kw)
            msg = SimpleNamespace(content=good_answer(fixture_input))
            return SimpleNamespace(choices=[SimpleNamespace(message=msg)], usage=None)

    gw = OpenAIGateway(client=SimpleNamespace(chat=SimpleNamespace(completions=Completions())))
    result = BlueEngine(LLMProposer(gw)).propose_with_trace(fixture_input("single_fp"))
    assert result.proposer_used == "llm:my-model"
    assert seen["response_format"] == {"type": "json_object"}


@pytest.mark.parametrize("cls", [AnthropicGateway, OpenAIGateway])
def test_gateway_errors_map_to_port_errors(cls):
    class APITimeoutError(Exception):
        pass

    def make(exc):
        def create(**kw):
            raise exc
        return SimpleNamespace(create=create)

    for exc, expected in ((APITimeoutError("slow"), ModelTimeout), (RuntimeError("boom"), ModelUnavailable)):
        client = SimpleNamespace(messages=make(exc), chat=SimpleNamespace(completions=make(exc)))
        with pytest.raises(expected):
            cls(client=client).generate("s", "t")


@pytest.mark.parametrize("cls", [AnthropicGateway, OpenAIGateway])
def test_missing_key_is_unavailable_not_a_crash(cls, gateway_env):
    with pytest.raises(ModelUnavailable, match="not set"):
        cls().generate("s", "t")


def test_factory_selects_by_environment(gateway_env):
    assert build_gateway() is None
    assert build_gateway("none") is None
    assert type(build_gateway("mock")).__name__ == "MockModelGateway"
    gateway_env.setenv("BLUE_MODEL_PROVIDER", "mock")
    assert type(build_gateway()).__name__ == "MockModelGateway"
    with pytest.raises(GatewayConfigError, match="ANTHROPIC_API_KEY"):
        build_gateway("anthropic")
    with pytest.raises(GatewayConfigError, match="OPENAI_API_KEY"):
        build_gateway("openai")
    with pytest.raises(GatewayConfigError, match="unknown"):
        build_gateway("nope")
    gateway_env.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    assert type(build_gateway("anthropic")).__name__ == "AnthropicGateway"


# --------------------------------------------------------------------------- #
# packaging
# --------------------------------------------------------------------------- #
def test_shipped_contracts_equal_the_repository_originals():
    originals = {
        "blue_input": REPO / "03_blue_role" / "interfaces" / "inputs" / "blue_input.schema.json",
        "blue_proposal": REPO / "00_shared_contracts" / "blue_proposal" / "blue_proposal.schema.json",
        "error_response": REPO / "00_shared_contracts" / "error_response" / "error_response.schema.json",
        "evidence_reference": REPO / "00_shared_contracts" / "telemetry_evidence" / "evidence_reference.schema.json",
    }
    if not all(p.is_file() for p in originals.values()):
        pytest.skip("repository contracts not available (package installed on its own)")
    for name, path in originals.items():
        assert json.loads(path.read_text(encoding="utf-8")) == json.loads(SCHEMA_FILES[name].read_text(encoding="utf-8")), \
            f"{name}: copy in autosoc_blue/contracts differs from {path}"


def test_prompts_are_package_data():
    assert (PKG / "prompts" / "blue_system.v0_1_0.md").is_file()
    assert (PKG / "prompts" / "blue_task.v0_1_0.md").is_file()


def test_package_imports_nothing_from_other_project_folders():
    forbidden = ("shared_services", "interfaces", "role_context", "scenarios", "retrieval", "agentic_rag_plus",
                 "ragplus", "rag_plus")
    for path in PKG.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] not in forbidden, f"{path.name} imports {name}"
                assert not name.split(".")[0][:2].isdigit(), f"{path.name} imports {name}"


def test_optional_sdks_are_only_imported_lazily():
    for name in ("anthropic_gateway.py", "openai_gateway.py"):
        tree = ast.parse((PKG / "adapters" / "gateways" / name).read_text(encoding="utf-8"))
        top_level = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        assert not any(getattr(n, "names", [None])[0].name in ("anthropic", "openai") for n in top_level)


def test_compat_aliases_still_work():
    import autosoc_blue.rule_edits as new_re
    import autosoc_blue.schemas.models as new_models
    import rule_edits
    import schemas.models

    assert schemas.models.BlueInput is new_models.BlueInput
    assert rule_edits.apply_edits is new_re.apply_edits
