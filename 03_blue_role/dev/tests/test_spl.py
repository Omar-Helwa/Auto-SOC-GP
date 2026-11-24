"""SPL support at the edges: parser, renderer, round trips, engine, CLI, HTTP."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from autosoc_blue.adapters.validators import LocalSigmaValidator
from autosoc_blue.cli import main
from autosoc_blue.core.engine import BlueEngine
from autosoc_blue.core.errors import InputError
from autosoc_blue.role import BlueRole
from autosoc_blue.rule_edits.apply import apply_edits, dump_rule
from autosoc_blue.schemas import validation
from autosoc_blue.schemas.models import BlueInput, RuleEdit, FieldCondition
from autosoc_blue.spl import SplError, SplUnsupported, convert_text, sigma_rule_to_spl, spl_to_sigma_rule

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "dev" / "fixtures"
EXAMPLES = ROOT / "interfaces" / "inputs" / "examples"
SPL_RULE = (FIXTURES / "rules" / "win-encoded-powershell.spl").read_text(encoding="utf-8").strip()
SIGMA_RULE = (FIXTURES / "rules" / "win-encoded-powershell.yml").read_text(encoding="utf-8")
V = LocalSigmaValidator()


def det(spl: str) -> dict:
    return spl_to_sigma_rule(spl)[0]["detection"]


def matches(spl: str, event: dict) -> bool:
    rule, _ = spl_to_sigma_rule(spl)
    return V.matches(dump_rule(rule), event)


# --------------------------------------------------------------------------- #
# Parsing, one construct at a time
# --------------------------------------------------------------------------- #
def test_scope_terms_are_kept_as_scope_not_logic():
    rule, _ = spl_to_sigma_rule('index=winlogs sourcetype=sysmon source="WinEventLog:Sysmon" Image="a.exe"')
    assert rule["x_spl_scope"] == {"index": ["winlogs"], "sourcetype": ["sysmon"], "source": ["WinEventLog:Sysmon"]}
    assert rule["detection"] == {"sel_image": {"Image": "a.exe"}, "condition": "sel_image"}


def test_time_modifiers_are_stripped_into_scope():
    rule, _ = spl_to_sigma_rule('index=w earliest=-24h latest=now Image="a.exe"')
    assert rule["x_spl_scope"]["earliest"] == ["-24h"] and rule["x_spl_scope"]["latest"] == ["now"]
    assert "earliest" not in json.dumps(rule["detection"])


def test_scope_with_or_of_indexes():
    rule, _ = spl_to_sigma_rule('(index=a OR index=b) Image="x.exe"')
    assert rule["x_spl_scope"]["index"] == ["a", "b"]


def test_wildcards_become_modifiers():
    d = det('A="*mid*" B="start*" C="*end" D="exact" E="a*b"')
    assert d["sel_a"] == {"A|contains": "mid"}
    assert d["sel_b"] == {"B|startswith": "start"}
    assert d["sel_c"] == {"C|endswith": "end"}
    assert d["sel_d"] == {"D": "exact"}
    assert d["sel_e"] == {"E": "a*b"}  # wildcard in the middle: raw pattern, equals


def test_or_on_one_field_becomes_one_selection_with_a_list():
    d = det('Image="*\\\\a.exe" OR Image="*\\\\b.exe"')
    assert d["sel_image"] == {"Image|endswith": ["\\a.exe", "\\b.exe"]}


def test_or_with_mixed_modifiers_becomes_list_of_maps():
    d = det('Image="x.exe" OR Image="*\\\\y.exe"')
    assert d["sel_image"] == [{"Image": "x.exe"}, {"Image|endswith": "\\y.exe"}]


def test_not_equal_and_NOT():
    d = det('A="x" B!="y" NOT C="z"')
    assert d["condition"] == "sel_a and not filter_b and not filter_c" or "not" in d["condition"]
    assert matches('A="x" B!="y" NOT C="z"', {"A": "x", "B": "q", "C": "w"})
    assert not matches('A="x" B!="y" NOT C="z"', {"A": "x", "B": "y", "C": "w"})
    assert not matches('A="x" B!="y" NOT C="z"', {"A": "x", "B": "q", "C": "z"})


def test_negated_groups_are_named_filter():
    assert "filter_b" in det('A="x" NOT B="y"')


def test_implicit_and_explicit_and_are_equal():
    assert det('A="x" B="y"') == det('A="x" AND B="y"')


def test_splunk_precedence_or_binds_tighter_than_and():
    # a b OR c  ==  a AND (b OR c)
    spl = 'A="1" B="2" OR C="3"'
    assert matches(spl, {"A": "1", "C": "3"})
    assert not matches(spl, {"A": "x", "B": "2"})


def test_parentheses_and_nesting():
    spl = '(A="1" OR B="2") AND NOT (C="3" AND D="4")'
    assert matches(spl, {"B": "2", "C": "3"})
    assert not matches(spl, {"B": "2", "C": "3", "D": "4"})
    assert not matches(spl, {"C": "9"})


def test_in_operator():
    spl = 'User IN ("CORP\\\\a", "CORP\\\\b", c*)'
    assert matches(spl, {"User": "CORP\\a"})
    assert matches(spl, {"User": "carol"})
    assert not matches(spl, {"User": "dave"})


def test_values_are_case_insensitive_field_names_are_not():
    assert matches('Image="*\\\\PowerShell.EXE"', {"Image": "c:\\windows\\powershell.exe"})
    assert not matches('Image="x"', {"image": "x"})


def test_backslash_escaping_in_windows_paths():
    d = det('Image="C:\\\\Windows\\\\System32\\\\cmd.exe"')
    assert d["sel_image"] == {"Image": "C:\\Windows\\System32\\cmd.exe"}
    # an unquoted path with single backslashes is tolerated
    assert det("Image=C:\\Windows\\cmd.exe")["sel_image"] == {"Image": "C:\\Windows\\cmd.exe"}
    # escaped quote
    assert det('CommandLine="*say \\"hi\\"*"')["sel_commandline"] == {"CommandLine|contains": 'say "hi"'}


def test_trailing_table_and_fields_are_ignored():
    rule, notes = spl_to_sigma_rule('A="x" | table A, B | fields - C')
    assert rule["detection"]["condition"] == "sel_a" and len(notes) == 2


def test_leading_search_keyword_is_accepted():
    assert det('search A="x"')["sel_a"] == {"A": "x"}


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("spl, word", [
    ('A="x" | stats count by A', "stats"),
    ('A="x" | eval b=1', "eval"),
    ('A="x" | rex field=A "(?<z>.+)"', "rex"),
    ('A="x" | regex A="^x"', "regex"),
    ('A="x" | lookup users u OUTPUT v', "lookup"),
    ('A="x" | table A | stats count', "stats"),
    ('A="x" [search B="y" | fields B]', "subsearch"),
    ('A="x" `my_macro(1)`', "macro"),
    ('A="x" TERM(abc)', "TERM"),
    ('CASE(Abc) A="x"', "CASE"),
    ('A="x" | where len(A)>3', "where"),
])
def test_unsupported_constructs_are_refused_in_plain_words(spl, word):
    with pytest.raises(SplUnsupported) as exc:
        spl_to_sigma_rule(spl)
    assert word.lower() in exc.value.message.lower()
    assert "not supported" in exc.value.message


@pytest.mark.parametrize("spl", [
    "A>5", "A>=5", "just_a_word", 'A="x" and B="y"', "A=", '(A="x"', 'A="x")', 'A="unterminated',
    "index=winlogs", 'index!="x" A="y"', 'A="x" NOT (index=a)', 'A="a\\*b"', 'A="a?b"',
])
def test_malformed_or_unsupported_inputs_raise(spl):
    with pytest.raises(SplError):
        spl_to_sigma_rule(spl)


def test_engine_answers_unsupported_spl_with_an_error_response(fixture_input):
    data = fixture_input("spl_single_fp")
    data["detection"]["rule_text"] += " | stats count by User"
    out = BlueRole().run(data)
    assert validation.validate_error_response(out).ok
    assert out["category"] == "validation"
    assert "stats" in out["message"] and "not supported" in out["message"]
    assert out["details"]["unsupported_spl"] == "| stats"
    with pytest.raises(InputError):
        BlueEngine().propose(data)


# --------------------------------------------------------------------------- #
# Renderer and round trips
# --------------------------------------------------------------------------- #
def test_sigma_to_spl_for_the_fixture_rule():
    text, _ = convert_text(SIGMA_RULE, "sigma", "spl", index="winlogs")
    assert text == SPL_RULE
    assert text == ('index=winlogs (Image="*\\\\powershell.exe" OR Image="*\\\\pwsh.exe") '
                    '(CommandLine="* -enc *" OR CommandLine="* -EncodedCommand *")')


def test_spl_to_sigma_to_spl_is_stable_on_canonical_searches():
    for spl in [SPL_RULE,
                'index=a A="x" (B="1" OR C="2*") NOT (D="d" AND E="*e")',
                'A="x" OR B="y"',
                'NOT A="x"',
                'A="*mid*" B="start*"']:
        sigma_text, _ = convert_text(spl, "spl", "sigma")
        back, _ = convert_text(sigma_text, "sigma", "spl")
        assert back == spl


def test_sigma_to_spl_to_sigma_keeps_the_meaning():
    spl, _ = convert_text(SIGMA_RULE, "sigma", "spl")
    sigma_back, _ = convert_text(spl, "spl", "sigma")
    events = [
        {"Image": "C:\\x\\powershell.exe", "CommandLine": "powershell -enc AAA"},
        {"Image": "C:\\x\\powershell.exe", "CommandLine": "powershell -nop"},
        {"Image": "C:\\x\\cmd.exe", "CommandLine": "cmd -enc"},
    ]
    for e in events:
        assert V.matches(SIGMA_RULE, e) == V.matches(sigma_back, e)


def test_sigma_conditions_with_quantifiers_render():
    rule = {"detection": {"selection_a": {"A": "1"}, "selection_b": {"B": "2"}, "filter_x": {"C": "3"},
                          "condition": "1 of selection_* and not filter_x"}}
    assert sigma_rule_to_spl(rule) == '(A="1" OR B="2") NOT C="3"'
    rule["detection"]["condition"] = "all of selection_*"
    assert sigma_rule_to_spl(rule) == 'A="1" B="2"'


def test_sigma_all_modifier_and_list_of_maps():
    rule = {"detection": {"s": {"CommandLine|contains|all": ["-a", "-b"]},
                          "t": [{"A": "1"}, {"B": "2", "C": "3"}], "condition": "s and t"}}
    assert sigma_rule_to_spl(rule) == 'CommandLine="*-a*" CommandLine="*-b*" (A="1" OR (B="2" AND C="3"))'


@pytest.mark.parametrize("value, expected", [
    ("C:\\Windows\\System32\\cmd.exe", 'Image="C:\\\\Windows\\\\System32\\\\cmd.exe"'),
    ('say "hi"', 'Image="say \\"hi\\""'),
    ("dir\\", 'Image="dir\\\\"'),
    ("*\\evil.exe", 'Image="*\\\\evil.exe"'),
])
def test_renderer_escapes_backslashes_quotes_and_keeps_wildcards(value, expected):
    assert sigma_rule_to_spl({"detection": {"s": {"Image": value}, "condition": "s"}}) == expected


def test_renderer_round_trips_awkward_values_exactly():
    for value in ["C:\\a\\b\\", 'q"uote', "back\\\\slash", "plain"]:
        spl = sigma_rule_to_spl({"detection": {"s": {"Image": value}, "condition": "s"}})
        rule, _ = spl_to_sigma_rule(spl)
        assert rule["detection"]["sel_image"] == {"Image": value}


def test_renderer_refuses_what_spl_cannot_say():
    with pytest.raises(SplUnsupported):
        sigma_rule_to_spl({"detection": {"s": {"A|re": "x.*"}, "condition": "s"}})
    with pytest.raises(SplUnsupported):
        sigma_rule_to_spl({"detection": {"s": {"A": "a?b"}, "condition": "s"}})
    with pytest.raises(SplUnsupported):
        sigma_rule_to_spl({"detection": {"s": {"A": None}, "condition": "s"}})
    with pytest.raises(SplUnsupported):
        sigma_rule_to_spl({"detection": {"s": {"A": "x"}, "condition": "s | count() > 5"}})


def test_add_exclusion_is_rendered_as_original_search_plus_not():
    rule, _ = spl_to_sigma_rule(SPL_RULE)
    cand = apply_edits(dump_rule(rule), [RuleEdit("add_exclusion", [
        FieldCondition("User", "equals", ["CORP\\svc_inventory"]),
        FieldCondition("ParentImage", "equals", ["C:\\Windows\\System32\\svchost.exe"]),
    ], "inventory")])
    assert sigma_rule_to_spl(cand.rule) == (
        SPL_RULE + ' NOT (User="CORP\\\\svc_inventory" AND ParentImage="C:\\\\Windows\\\\System32\\\\svchost.exe")')


def test_narrow_selection_is_rendered_as_extra_field_conditions():
    rule, _ = spl_to_sigma_rule(SPL_RULE)
    cand = apply_edits(dump_rule(rule), [RuleEdit(
        "narrow_selection", [FieldCondition("IntegrityLevel", "equals", ["High"])], "x", "sel_commandline")])
    assert sigma_rule_to_spl(cand.rule) == (
        'index=winlogs (Image="*\\\\powershell.exe" OR Image="*\\\\pwsh.exe") '
        '(CommandLine="* -enc *" OR CommandLine="* -EncodedCommand *") IntegrityLevel="High"')


# --------------------------------------------------------------------------- #
# Engine on SPL input
# --------------------------------------------------------------------------- #
def _spl_inputs():
    return ["spl_single_fp", "spl_multi_fp", "spl_narrow_only", "spl_needs_commandline"]


@pytest.mark.parametrize("name", _spl_inputs())
def test_propose_on_spl_matches_propose_on_sigma(name, fixture_input):
    sigma_input = fixture_input(name.removeprefix("spl_"))
    spl_input = fixture_input(name)
    a = BlueEngine().propose(sigma_input)
    b = BlueEngine().propose(spl_input)
    assert validation.validate_blue_proposal(b).ok
    strip = lambda edits: [{k: v for k, v in e.items() if k != "target_selection"} for e in edits]  # names differ
    assert strip(a["edits"]) == strip(b["edits"])
    assert [e.get("target_selection") is None for e in a["edits"]] == [e.get("target_selection") is None for e in b["edits"]]
    assert a["addressed_false_positives"] == b["addressed_false_positives"]


def test_full_propose_on_spl_removes_fp_keeps_attacks_and_renders(fixture_input):
    data = fixture_input("spl_single_fp")
    inp = BlueInput.from_dict(data)
    out = BlueEngine().propose(data, render="spl")
    assert set(out) == {"blue_proposal", "edited_rule"}
    assert validation.validate_blue_proposal(out["blue_proposal"]).ok  # contract object untouched
    assert out["edited_rule"]["format"] == "spl"
    edited = out["edited_rule"]["text"]
    assert edited.startswith(SPL_RULE + " NOT (")
    # the rendered SPL really does what the proposal promises, checked with the local matcher
    rule, _ = spl_to_sigma_rule(edited)
    text = dump_rule(rule)
    assert not any(V.matches(text, c.observed_fields) for c in inp.false_positives)
    assert all(V.matches(text, c.observed_fields) for c in inp.must_detect)


def test_propose_with_sigma_input_can_render_spl_too(fixture_input):
    out = BlueEngine().propose(fixture_input("single_fp"), render="spl")
    assert out["edited_rule"]["text"].startswith('(Image="*\\\\powershell.exe" OR Image="*\\\\pwsh.exe") ')
    assert " NOT (" in out["edited_rule"]["text"]


def test_render_sigma_returns_the_edited_yaml(fixture_input):
    out = BlueEngine().propose(fixture_input("spl_single_fp"), render="sigma")
    assert out["edited_rule"]["format"] == "sigma"
    assert "filter_autosoc_1" in out["edited_rule"]["text"]


def test_blue_role_run_still_returns_only_the_contract_object(fixture_input):
    role = BlueRole()
    out = role.run(fixture_input("spl_single_fp"))
    assert validation.validate_blue_proposal(out).ok and "edited_rule" not in out
    assert role.last_edited_rule["format"] == "spl"


def test_llm_prompt_shows_spl_and_normalised_conditions(fixture_input):
    from autosoc_blue.core.context import build_context
    from autosoc_blue.prompts import registry

    data = fixture_input("spl_single_fp")
    ctx = build_context(BlueInput.from_dict(data))
    task = registry.render(data["prompt_version"], ctx)["task"]
    assert "Current Splunk search (SPL):" in task and "```spl" in task and SPL_RULE in task
    assert "Normalised field conditions" in task
    assert "sel_image" in task and "Image endswith" in task
    assert "```yaml" not in task
    sigma_task = registry.render(data["prompt_version"], build_context(BlueInput.from_dict(
        fixture_input("single_fp"))))["task"]
    assert "Current Sigma rule:" in sigma_task and "```yaml" in sigma_task


@pytest.mark.parametrize("provider", ["mock"])
def test_mock_llm_provider_works_on_spl(provider, fixture_input, gateway_env):
    from autosoc_blue.factory import build_engine

    out = build_engine(provider).propose(fixture_input("spl_multi_fp"))
    assert validation.validate_blue_proposal(out).ok


def test_spl_inputs_validate_against_the_contract():
    from autosoc_blue.schemas import validation as v

    good = json.loads((EXAMPLES / "valid_blue_input_spl.json").read_text(encoding="utf-8"))
    assert v.validate_blue_input({k: x for k, x in good.items() if not k.startswith("_")}).ok
    bad = json.loads((EXAMPLES / "invalid_blue_input_spl.json").read_text(encoding="utf-8"))
    bad = {k: x for k, x in bad.items() if not k.startswith("_")}
    assert v.validate_blue_input(bad).ok  # schema-valid ...
    assert BlueRole().run(bad)["category"] == "validation"  # ... but Blue refuses the construct
    legacy = dict(good, detection=dict(good["detection"], rule_format="splunk_spl"))
    assert not v.validate_blue_input({k: x for k, x in legacy.items() if not k.startswith("_")}).ok


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
INPUTS = FIXTURES / "inputs"


def test_cli_propose_render_spl_writes_the_rule_beside_the_proposal(tmp_path, gateway_env):
    out = tmp_path / "proposal.json"
    assert main(["propose", "--input", str(INPUTS / "spl_single_fp.json"), "--out", str(out), "--render", "spl"]) == 0
    assert validation.validate_blue_proposal(json.loads(out.read_text(encoding="utf-8"))).ok
    spl = (tmp_path / "proposal.edited.spl").read_text(encoding="utf-8")
    assert spl.startswith(SPL_RULE + " NOT (")


def test_cli_propose_rule_out_and_stdout(tmp_path, capsys, gateway_env):
    target = tmp_path / "edited.spl"
    assert main(["propose", "--input", str(INPUTS / "spl_single_fp.json"), "--render", "spl",
                 "--rule-out", str(target)]) == 0
    assert target.read_text(encoding="utf-8").startswith("index=winlogs")
    assert main(["propose", "--input", str(INPUTS / "spl_single_fp.json"), "--render", "spl"]) == 0
    assert '"edited_rule"' in capsys.readouterr().out
    assert main(["propose", "--input", str(INPUTS / "spl_single_fp.json"), "--rule-out", str(target)]) == 2


def test_cli_convert_both_ways(tmp_path, capsys):
    assert main(["convert", "--from", "sigma", "--to", "spl", "--index", "winlogs",
                 str(FIXTURES / "rules" / "win-encoded-powershell.yml")]) == 0
    assert capsys.readouterr().out.strip() == SPL_RULE
    out = tmp_path / "rule.yml"
    assert main(["convert", "--from", "spl", "--to", "sigma", str(FIXTURES / "rules" / "win-encoded-powershell.spl"),
                 "--out", str(out)]) == 0
    assert yaml.safe_load(out.read_text(encoding="utf-8"))["detection"]["condition"] == "sel_image and sel_commandline"


def test_cli_convert_refusal_is_explained(tmp_path, capsys):
    bad = tmp_path / "bad.spl"
    bad.write_text('A="x" | stats count', encoding="utf-8")
    assert main(["convert", "--from", "spl", "--to", "sigma", str(bad)]) == 1
    assert "not supported" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
@pytest.fixture
def client(gateway_env):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from autosoc_blue.api import create_app

    return TestClient(create_app())


def test_http_propose_render_spl(client, fixture_input):
    data = fixture_input("spl_single_fp")
    resp = client.post("/propose?render=spl", json=data)
    assert resp.status_code == 200
    body = resp.json()
    assert validation.validate_blue_proposal(body["blue_proposal"]).ok
    assert body["edited_rule"]["format"] == "spl" and " NOT (" in body["edited_rule"]["text"]
    plain = client.post("/propose", json=data).json()
    assert "edited_rule" not in plain and validation.validate_blue_proposal(plain).ok


def test_http_propose_unsupported_spl_is_422_error_response(client, fixture_input):
    data = fixture_input("spl_single_fp")
    data["detection"]["rule_text"] += " | eval x=1"
    resp = client.post("/propose", json=data)
    assert resp.status_code == 422 and validation.validate_error_response(resp.json()).ok


def test_http_convert(client):
    resp = client.post("/convert", json={"from": "sigma", "to": "spl", "rule_text": SIGMA_RULE, "index": "winlogs"})
    assert resp.status_code == 200 and resp.json()["text"] == SPL_RULE
    back = client.post("/convert", json={"from": "spl", "to": "sigma", "rule_text": SPL_RULE})
    assert "sel_image" in back.json()["text"]
    bad = client.post("/convert", json={"from": "spl", "to": "sigma", "rule_text": "A=1 | stats count"})
    assert bad.status_code == 422 and validation.validate_error_response(bad.json()).ok
    assert client.post("/convert", json={"from": "x"}).status_code == 422
