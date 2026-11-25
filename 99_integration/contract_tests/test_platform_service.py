"""Mock-backed tests for the assembled Platform adapter.

Every Splunk search goes through the real ``SplunkClient`` and the real
``ManualCLIApprovalAuthorizer`` (with a scripted operator) to the local
Splunk REST stub; no live Splunk, model, or MongoDB service is contacted.
The reviewed label set is a test fixture written to a temporary directory.

Run from the repository root:  python -m pytest 99_integration/contract_tests -q
"""

from __future__ import annotations

import copy
import fnmatch
import importlib.util
import json
import re
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = REPO_ROOT / "00_shared_contracts"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _load_runner():
    path = REPO_ROOT / "99_integration" / "assembled_runs" / "run_with_real_red_and_blue.py"
    name = "assembled_runner_under_test"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_splunk_stub():
    # ``dev`` is also 01_orchestrator's package name, so load the stub by path.
    path = REPO_ROOT / "05_platform_integrations" / "dev" / "mocks" / "splunk" / "server.py"
    spec = importlib.util.spec_from_file_location("platform_splunk_stub", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runner = _load_runner()
platform_module = runner._load_adapter("platform_service")
create_server = _load_splunk_stub().create_server

from evidence_store.store import EvidenceStore  # noqa: E402
from proposal_execution import ProposalExecutionService  # noqa: E402
from shared_services.controller.services import ServiceAdapterError  # noqa: E402
from splunk_execution import ManualCLIApprovalAuthorizer, SplunkClient, SplunkConfig  # noqa: E402
from splunk_execution.approval import bound_approval_id  # noqa: E402
from validation.events import normalize_frozen_set_event, stable_event_id  # noqa: E402
from validation.labels import evaluation_set_checksum  # noqa: E402

INDEX = "autosoc_lab"
EVAL_SET = "evalset-test-v1"
RULE_TEXT = 'Image="*\\\\powershell.exe" CommandLine="*-EncodedCommand*"'
EDIT_CONSTRAINTS = {
    "allowed_operations": ["add_exclusion"],
    "allowed_fields": ["User", "ParentImage", "Image", "CommandLine"],
    "attacker_controllable_fields": ["CommandLine"],
    "max_edits": 2,
}

EVENTS = {
    "evt-fp-inventory": ("benign", {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile -EncodedCommand RwBlAHQALQBDAGkAbQ==",
        "ParentImage": "C:\\Windows\\System32\\svchost.exe",
        "User": "CORP\\svc_inventory",
    }),
    "evt-atk-office": ("attack", {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -w hidden -EncodedCommand SQBFAFgAIAAoAE4A",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "User": "CORP\\alice",
    }),
    "evt-atk-cmd": ("attack", {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -nop -EncodedCommand JABjAD0ATgBlAHcA",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "User": "CORP\\bob",
    }),
    "evt-benign-notepad": ("benign", {
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "CommandLine": "notepad.exe C:\\notes.txt",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "User": "CORP\\carol",
    }),
}
EVENT_IDS = sorted(EVENTS)
DATASET = {
    "dataset_id": "lab-sysmon",
    "dataset_version": "2026.11.1",
    "evaluation_set_id": EVAL_SET,
    "evaluation_set_checksum": evaluation_set_checksum(EVENT_IDS),
}


# ------------------------------------------------------------------ fixtures


def splunk_record(event_id: str, **overrides) -> dict:
    _, fields = EVENTS[event_id]
    record = {
        "_time": "2026-11-10T09:00:00.000+00:00",
        "_cd": f"0:{EVENT_IDS.index(event_id)}",
        "_bkt": "autosoc_lab~1~ABC",
        "_raw": "<Event>...</Event>",
        "event_id": event_id,
        "autosoc_eval_set": EVAL_SET,
        "index": INDEX,
        "host": "lab-host-01",
        "source": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "sourcetype": "XmlWinEventLog",
        **fields,
    }
    record.update(overrides)
    return record


def label_set(*, reviewed: bool = True) -> dict:
    return {
        "contract_version": "0.1.0",
        "label_set_id": f"labels-{EVAL_SET}",
        "label_set_version": "1",
        "dataset": dict(DATASET),
        "coverage": {"total_events": len(EVENT_IDS), "complete": reviewed},
        "labels": [
            {
                "event_id": event_id,
                "label": EVENTS[event_id][0],
                "source": "public_dataset",
                "scenario_id": f"scenario-{event_id}",
                "review": (
                    {"status": "reviewed", "reviewer": "test-fixture-analyst",
                     "reviewed_at": "2026-11-10T09:00:00Z"}
                    if reviewed else {"status": "unreviewed"}
                ),
            }
            for event_id in EVENT_IDS
        ],
    }


def write_labels(root: Path, labels: dict) -> None:
    path = root / EVAL_SET / "labels"
    path.mkdir(parents=True, exist_ok=True)
    (path / "reviewed_label_set.json").write_text(json.dumps(labels), encoding="utf-8")


def round_request(task_id: str) -> dict:
    request = json.loads(
        (CONTRACTS / "round_request" / "examples" / "valid_round_request.json").read_text(encoding="utf-8")
    )
    request.pop("permitted_evidence_refs", None)
    request["task_id"] = task_id
    request["detection"]["rule_text"] = RULE_TEXT
    request["dataset"] = dict(DATASET)
    return request


def red_proposal(task_id: str) -> dict:
    proposal = json.loads(
        (CONTRACTS / "red_proposal" / "examples" / "valid_red_proposal.json").read_text(encoding="utf-8")
    )
    proposal["task_id"] = task_id
    proposal["proposal_id"] = f"red-{task_id}"
    return proposal


def blue_proposal(task_id: str) -> dict:
    proposal = json.loads(
        (CONTRACTS / "blue_proposal" / "examples" / "valid_blue_proposal_spl.json").read_text(encoding="utf-8")
    )
    proposal["task_id"] = task_id
    proposal.pop("edited_rule", None)
    return proposal


# ----------------------------------------------------- mock Splunk evaluation

_TERM = re.compile(r'([A-Za-z][A-Za-z0-9_]*)="((?:\\.|[^"\\])*)"')
_ITEM = re.compile(r'\((?P<any>[^()]*)\)|(?P<one>[A-Za-z][A-Za-z0-9_]*="(?:\\.|[^"\\])*")')


def _term_matches(fields: dict, field: str, raw: str) -> bool:
    pattern = re.sub(r"\\(.)", r"\1", raw)
    return field in fields and fnmatch.fnmatchcase(fields[field].lower(), pattern.lower())


def _excluded(fields: dict, group: str) -> bool:
    for item in _ITEM.finditer(group):
        terms = _TERM.findall(item.group("any") or item.group("one"))
        if not any(_term_matches(fields, name, raw) for name, raw in terms):
            return False
    return True


def _rule_matches(fields: dict) -> bool:
    return fields["Image"].lower().endswith("\\powershell.exe") and "-encodedcommand" in fields["CommandLine"].lower()


class SplunkLab:
    """Evaluate the three Platform search shapes over the frozen fixture events."""

    def __init__(self) -> None:
        self.telemetry_spl = f"search index={INDEX} autosoc_eval_set::{EVAL_SET}"
        self.baseline_spl = f"{self.telemetry_spl} ({RULE_TEXT})"
        self.records = {event_id: splunk_record(event_id) for event_id in EVENT_IDS}
        self.overrides: dict[str, list[dict]] = {}

    def __call__(self, params: dict) -> list[dict]:
        spl = params["search"][0]
        for prefix, records in self.overrides.items():
            if spl.startswith(prefix):
                return records
        if spl == self.telemetry_spl:
            return list(self.records.values())
        matched = [r for r in self.records.values() if _rule_matches(r)]
        if spl == self.baseline_spl:
            return matched
        prefix = "search (" + self.baseline_spl[len("search "):] + ") NOT ("
        if not spl.startswith(prefix) or not spl.endswith(")"):
            raise AssertionError(f"unexpected SPL reached Splunk: {spl}")
        groups = spl[len(prefix):-1].split(") NOT (")
        return [r for r in matched if not any(_excluded(r, group) for group in groups)]


class Operator:
    """Scripted approver: types the approval reference shown in each prompt."""

    def __init__(self) -> None:
        self.prompts: list[str] = []
        self.approve = True

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        reference = next(
            line.split(": ", 1)[1] for line in prompt.splitlines() if line.startswith("Approval reference: ")
        )
        return f"APPROVE {reference}" if self.approve else "no"


@pytest.fixture(scope="module")
def server():
    stub = create_server()
    thread = threading.Thread(target=stub.serve_forever, daemon=True)
    thread.start()
    yield stub
    stub.shutdown()
    stub.server_close()
    thread.join(timeout=2)


@pytest.fixture
def lab(server):
    model = SplunkLab()
    server.response_mode = "success"
    server.responder = model
    server.last_search = None
    server.searches.clear()
    yield model
    server.responder = None


@pytest.fixture
def operator():
    return Operator()


@pytest.fixture
def make_platform(server, lab, operator, tmp_path):
    write_labels(tmp_path / "prepared", label_set())

    def build(*, max_events: int = 100, timeout: float = 2.0, settings_max_events: int | None = 100,
              edit_constraints: dict = EDIT_CONSTRAINTS, event_normalizer=None):
        store = EvidenceStore(tmp_path / "evidence")
        client = SplunkClient(
            SplunkConfig(
                base_url=f"http://127.0.0.1:{server.server_port}",
                username="test-user",
                password="test-password",
                allow_insecure_http=True,
                max_events=max_events,
                timeout_seconds=timeout,
            ),
            ManualCLIApprovalAuthorizer(INDEX, require_binding=True, confirm=operator),
        )
        return platform_module.SplunkPlatformService(
            ProposalExecutionService(client, store, event_normalizer=event_normalizer),
            store,
            settings=platform_module.PlatformSearchSettings(index=INDEX, max_events=settings_max_events),
            edit_constraints=edit_constraints,
            prepared_root=tmp_path / "prepared",
        )

    return build


def run_through_verification(platform, task_id: str = "round-test-1"):
    request = round_request(task_id)
    red = red_proposal(task_id)
    collected = platform.collect_telemetry(request, red)
    verified = platform.verify_evidence(request, red, collected.raw_output_ref)
    return request, red, collected, verified


def approved_spl(prompt: str) -> str:
    return next(line[len("SPL: "):] for line in prompt.splitlines() if line.startswith("SPL: "))


# ------------------------------------------------------------- approvals


def test_each_search_is_approved_with_its_exact_binding(make_platform, server, operator):
    platform = make_platform()
    request, red, collected, verified = run_through_verification(platform)

    assert len(operator.prompts) == len(server.searches) == 2
    for prompt, search in zip(operator.prompts, server.searches):
        assert search["search"] == [approved_spl(prompt)]
        assert search["earliest_time"] == ["0"] and search["latest_time"] == ["now"]
        assert f"Proposal: {red['proposal_id']}" in prompt
        assert f"evaluation_set_checksum={DATASET['evaluation_set_checksum']}" in prompt
        assert f"Index scope: {INDEX}" in prompt
    telemetry = verified.messages["telemetry_evidence"]
    assert collected.raw_output_ref == f"evidence_store:{telemetry['evidence_id']}"
    assert telemetry["execution"]["approval_id"] in operator.prompts[0]
    assert telemetry["execution"]["approval_id"].startswith("apv-")


def test_rejected_approval_never_reaches_splunk(make_platform, server, operator):
    operator.approve = False
    platform = make_platform()
    with pytest.raises(ServiceAdapterError) as error:
        platform.collect_telemetry(round_request("round-test-1"), red_proposal("round-test-1"))
    assert error.value.category == "validation"
    assert "not approved" in str(error.value)
    assert len(operator.prompts) == 1 and server.searches == []


def test_altered_request_is_refused_without_prompting(make_platform, operator):
    platform = make_platform()
    request = platform._approved_request(
        round_request("round-test-1"), "telemetry", "red-round-test-1",
        f"search index={INDEX} autosoc_eval_set::{EVAL_SET}",
    )
    authorizer = ManualCLIApprovalAuthorizer(INDEX, require_binding=True, confirm=operator)
    assert authorizer.is_approved(request)
    for altered in (
        replace(request, spl=request.spl + " EventID=1"),
        replace(request, proposal_id="red-other"),
        replace(request, dataset={**DATASET, "dataset_version": "other"}),
        replace(request, earliest_time="-1h"),
        replace(request, task_id="round-other"),
    ):
        assert not authorizer.is_approved(altered)
    assert len(operator.prompts) == 1
    assert request.approval_id == bound_approval_id(request, INDEX)


def test_hosted_provider_policy_refuses_private_or_unconfirmed_telemetry():
    assert runner._hosted_model_refusal("none", ["lab_telemetry"], False) is None
    assert "non-public" in runner._hosted_model_refusal("groq", ["public_dataset", "lab_telemetry"], True)
    assert "--allow-public" in runner._hosted_model_refusal("xai", ["public_dataset"], False)
    assert runner._hosted_model_refusal("groq", ["public_dataset"], True) is None


# --------------------------------------------------------- Splunk responses


def test_successful_telemetry_is_persisted_and_complete(make_platform, tmp_path):
    platform = make_platform()
    _, _, collected, verified = run_through_verification(platform)
    telemetry = verified.messages["telemetry_evidence"]
    assert EvidenceStore(tmp_path / "evidence").get(telemetry["evidence_id"]) == telemetry
    assert telemetry["execution"]["truncated"] is False
    assert sorted(event["event_id"] for event in telemetry["events"]) == EVENT_IDS
    assert collected.raw_output["event_count"] == len(EVENT_IDS)


def test_empty_result_is_rejected(make_platform, lab):
    lab.overrides["search index="] = []
    with pytest.raises(ServiceAdapterError, match="returned no events") as error:
        make_platform().collect_telemetry(round_request("round-test-1"), red_proposal("round-test-1"))
    assert error.value.category == "missing_information"


def test_truncated_result_is_rejected(make_platform):
    platform = make_platform(max_events=2, settings_max_events=None)
    with pytest.raises(ServiceAdapterError, match="truncated after 2 events") as error:
        platform.collect_telemetry(round_request("round-test-1"), red_proposal("round-test-1"))
    assert error.value.category == "missing_information"


def test_result_cap_below_frozen_set_fails_before_any_search(make_platform, server, operator):
    platform = make_platform(max_events=2, settings_max_events=2)
    with pytest.raises(ServiceAdapterError, match="would be truncated"):
        platform.collect_telemetry(round_request("round-test-1"), red_proposal("round-test-1"))
    assert operator.prompts == [] and server.searches == []


def test_timeout_is_classified_as_retryable_timeout(make_platform, server):
    server.response_mode = "delay"
    server.delay_seconds = 0.3
    try:
        with pytest.raises(ServiceAdapterError) as error:
            make_platform(timeout=0.05).collect_telemetry(
                round_request("round-test-1"), red_proposal("round-test-1")
            )
    finally:
        # Let the stub finish the abandoned request so it is not logged in a later test.
        time.sleep(server.delay_seconds + 0.2)
        server.response_mode = "success"
    assert error.value.category == "timeout" and error.value.retryable is True
    assert error.value.details["execution"]["status"] == "failed"


def test_unavailable_splunk_is_classified_as_dependency(make_platform, server):
    server.response_mode = "unavailable"
    try:
        with pytest.raises(ServiceAdapterError, match="HTTP 503") as error:
            make_platform().collect_telemetry(round_request("round-test-1"), red_proposal("round-test-1"))
    finally:
        server.response_mode = "success"
    assert error.value.category == "dependency" and error.value.retryable is True


def test_tls_failure_is_not_retried_and_explains_the_ca_setting():
    category, retryable, hint = platform_module._classify_splunk_failure(
        "Could not connect to Splunk: [SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate"
    )
    assert (category, retryable) == ("dependency", False)
    assert "AUTOSOC_SPLUNK_CA_CERT" in hint


# ------------------------------------------- event identity and dataset joins


def test_events_without_the_indexed_event_id_are_rejected(make_platform, lab):
    record = splunk_record("evt-atk-cmd")
    del record["event_id"]  # the client falls back to _cd, which is not a label identity
    lab.records["evt-atk-cmd"] = record
    with pytest.raises(ServiceAdapterError, match="outside the frozen label set") as error:
        make_platform().collect_telemetry(round_request("round-test-1"), red_proposal("round-test-1"))
    assert error.value.category == "validation"


def test_missing_labelled_events_are_rejected(make_platform, lab):
    del lab.records["evt-benign-notepad"]
    with pytest.raises(ServiceAdapterError, match="missing 1 of 4 labelled events"):
        make_platform().collect_telemetry(round_request("round-test-1"), red_proposal("round-test-1"))


def test_all_artifacts_share_event_ids_and_the_frozen_dataset(make_platform, server, operator):
    platform = make_platform()
    request, red, _, verified = run_through_verification(platform)
    telemetry = verified.messages["telemetry_evidence"]
    labels = verified.messages["reviewed_label_set"]
    baseline = verified.messages["baseline_match_set"]
    candidate = platform.execute_candidate(request, blue_proposal(request["task_id"]), baseline)
    candidate_matches = candidate.messages["candidate_match_set"]

    label_ids = {label["event_id"] for label in labels["labels"]}
    assert {event["event_id"] for event in telemetry["events"]} == label_ids
    assert {m["event_id"] for m in baseline["matches"]} == {"evt-atk-cmd", "evt-atk-office", "evt-fp-inventory"}
    assert {m["event_id"] for m in candidate_matches["matches"]} == {"evt-atk-cmd", "evt-atk-office"}
    for artifact in (labels, baseline, candidate_matches):
        assert artifact["dataset"] == request["dataset"] == DATASET
    assert evaluation_set_checksum(label_ids) == DATASET["evaluation_set_checksum"]
    for prompt in operator.prompts:
        assert f"dataset_id={DATASET['dataset_id']}" in prompt
        assert f"dataset_version={DATASET['dataset_version']}" in prompt
        assert f"evaluation_set_id={EVAL_SET}" in prompt


def test_tampered_evidence_and_foreign_references_are_rejected(make_platform, tmp_path):
    platform = make_platform()
    request, red = round_request("round-test-1"), red_proposal("round-test-1")
    collected = platform.collect_telemetry(request, red)
    with pytest.raises(ServiceAdapterError, match="not a Platform evidence_store reference"):
        platform.verify_evidence(request, red, "smoke://telemetry/round-test-1")
    evidence_id = collected.raw_output_ref.split(":", 1)[1]
    path = tmp_path / "evidence" / f"{evidence_id}.json"
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored["events"] = stored["events"][:1]
    path.write_text(json.dumps(stored), encoding="utf-8")
    with pytest.raises(ServiceAdapterError, match="integrity") as error:
        platform.verify_evidence(request, red, collected.raw_output_ref)
    assert error.value.category == "validation"


def test_evidence_from_another_proposal_is_rejected(make_platform):
    platform = make_platform()
    request = round_request("round-test-1")
    collected = platform.collect_telemetry(request, red_proposal("round-test-1"))
    other = red_proposal("round-test-1")
    other["proposal_id"] = "red-someone-else"
    with pytest.raises(ServiceAdapterError, match="different task, proposal, or detection"):
        platform.verify_evidence(request, other, collected.raw_output_ref)


# ------------------------------------------------ label readiness gates


def _incomplete(labels: dict) -> None:
    labels["coverage"] = {"total_events": 4, "complete": False}


def _unreviewed(labels: dict) -> None:
    labels["coverage"]["complete"] = False
    for label in labels["labels"]:
        label["review"] = {"status": "unreviewed"}


def _other_version(labels: dict) -> None:
    labels["dataset"]["dataset_version"] = "2026.12.0"


@pytest.mark.parametrize("mutate, message", [
    (_incomplete, "coverage.complete is false"),
    (_unreviewed, "4 of 4 labels are not reviewed"),
    (_other_version, "dataset.dataset_version"),
])
def test_unready_labels_are_rejected_before_any_search(make_platform, tmp_path, server, operator, mutate, message):
    platform = make_platform()
    labels = label_set()
    mutate(labels)
    write_labels(tmp_path / "prepared", labels)
    with pytest.raises(ServiceAdapterError, match=message) as error:
        platform.collect_telemetry(round_request("round-test-1"), red_proposal("round-test-1"))
    assert error.value.category == "missing_information"
    assert operator.prompts == [] and server.searches == []
    stored = json.loads((tmp_path / "prepared" / EVAL_SET / "labels" / "reviewed_label_set.json").read_text())
    assert stored == labels, "the Platform must not rewrite label review state"


def test_blue_context_rejects_unreviewed_or_drifted_label_artifacts(make_platform):
    platform = make_platform()
    request, _, _, verified = run_through_verification(platform)
    artifacts = dict(verified.messages)

    unreviewed = copy.deepcopy(artifacts["reviewed_label_set"])
    unreviewed["coverage"]["complete"] = False
    unreviewed["labels"][0]["review"] = {"status": "unreviewed"}
    with pytest.raises(ServiceAdapterError, match="not judge-ready"):
        platform.build_blue_context(request, {**artifacts, "reviewed_label_set": unreviewed})

    drifted = copy.deepcopy(artifacts["reviewed_label_set"])
    drifted["labels"][0]["scenario_id"] = "edited-after-verification"
    with pytest.raises(ServiceAdapterError, match="differs from the frozen label source"):
        platform.build_blue_context(request, {**artifacts, "reviewed_label_set": drifted})

    with pytest.raises(ServiceAdapterError, match="missing"):
        platform.build_blue_context(request, {"telemetry_evidence": artifacts["telemetry_evidence"]})


def test_blue_context_projects_only_permitted_fields(make_platform):
    platform = make_platform()
    request, _, _, verified = run_through_verification(platform)
    context = platform.build_blue_context(request, verified.messages)
    view = context.evidence_view
    telemetry_id = verified.messages["telemetry_evidence"]["evidence_id"]

    assert [case["evidence_reference"]["provenance_ref"].split("#")[1].split(";")[0]
            for case in view["false_positives"]] == ["evt-fp-inventory"]
    assert sorted(case["evidence_reference"]["provenance_ref"].split("#")[1].split(";")[0]
                  for case in view["must_detect"]) == ["evt-atk-cmd", "evt-atk-office"]
    for case in view["false_positives"] + view["must_detect"]:
        assert case["evidence_reference"]["evidence_id"] == telemetry_id
        assert set(case["observed_fields"]) <= {"User", "ParentImage", "Image", "CommandLine"}
    assert context.edit_constraints == EDIT_CONSTRAINTS
    assert context.blue_detection["rule_text"] == RULE_TEXT
    assert context.prior_blue_edits is None


# --------------------------------------------------- candidate execution


def test_candidate_spl_is_the_compiled_rule_and_its_approval(make_platform, server, operator):
    platform = make_platform()
    request, _, _, verified = run_through_verification(platform)
    output = platform.execute_candidate(
        request, blue_proposal(request["task_id"]), verified.messages["baseline_match_set"]
    )
    candidate_rule = output.messages["candidate_rule"]
    compiled = candidate_rule["compiled_rule"]["text"]

    assert server.searches[-1]["search"] == [compiled]
    assert approved_spl(operator.prompts[-1]) == compiled
    assert output.raw_output["approval_id"] in operator.prompts[-1]
    assert candidate_rule["compiled_rule"]["sha256"] == output.raw_output["spl_sha256"]
    assert output.messages["candidate_match_set"]["candidate_ref"] == candidate_rule["candidate_id"]
    assert candidate_rule["candidate_rule_version"].startswith("3.2.0-cand-")
    assert "baseline_match_set" not in output.messages


def test_candidate_requires_the_verified_baseline(make_platform):
    platform = make_platform()
    request, _, _, verified = run_through_verification(platform)
    proposal = blue_proposal(request["task_id"])
    with pytest.raises(ServiceAdapterError, match="requires the verified baseline") as error:
        platform.execute_candidate(request, proposal, None)
    assert error.value.category == "missing_information"

    foreign = copy.deepcopy(verified.messages["baseline_match_set"])
    foreign["dataset"]["dataset_version"] = "2026.12.0"
    with pytest.raises(ServiceAdapterError, match="dataset differs"):
        platform.execute_candidate(request, proposal, foreign)

    unbound = copy.deepcopy(verified.messages["baseline_match_set"])
    unbound["execution"]["search_ref"] = "round-test-1:telemetry"
    with pytest.raises(ServiceAdapterError, match="search_ref"):
        platform.execute_candidate(request, proposal, unbound)


def test_candidate_rejections(make_platform, lab, server):
    platform = make_platform()
    request, _, _, verified = run_through_verification(platform)
    baseline = verified.messages["baseline_match_set"]
    searches_before = len(server.searches)

    narrow = blue_proposal(request["task_id"])
    narrow["edits"][0] = {
        "operation": "narrow_selection",
        "target_selection": "selection",
        "conditions": [{"field": "User", "modifier": "equals", "values": ["CORP\\alice"]}],
        "reason": "Narrow the selection.",
    }
    with pytest.raises(ServiceAdapterError, match="did not allow"):
        platform.execute_candidate(request, narrow, baseline)

    wrong_task = blue_proposal("round-other")
    with pytest.raises(ServiceAdapterError, match="task_id"):
        platform.execute_candidate(request, wrong_task, baseline)
    assert len(server.searches) == searches_before

    lab.overrides["search (index="] = [splunk_record(event_id) for event_id in EVENT_IDS]
    with pytest.raises(ServiceAdapterError, match="truncated or partial"):
        make_platform(max_events=2, settings_max_events=None).execute_candidate(
            request, blue_proposal(request["task_id"]), baseline
        )

    lab.overrides["search (index="] = [{**splunk_record("evt-atk-cmd"), "event_id": "evt-unknown"}]
    with pytest.raises(ServiceAdapterError, match="outside the frozen label set"):
        platform.execute_candidate(request, blue_proposal(request["task_id"]), baseline)


def test_unsupported_edit_operations_are_refused_at_construction(make_platform):
    with pytest.raises(ValueError, match="no named selections"):
        make_platform(edit_constraints={**EDIT_CONSTRAINTS, "allowed_operations": ["narrow_selection"]})


def test_rule_outside_the_index_scope_is_refused(make_platform):
    request = round_request("round-test-1")
    request["detection"]["rule_text"] = "index=production " + RULE_TEXT
    with pytest.raises(ServiceAdapterError, match="outside the approved scope"):
        make_platform().preflight(request)


# ------------------------------------------------------------ composition


def _splunk_env(monkeypatch, tmp_path, **values):
    env_file = tmp_path / "empty.env"
    env_file.write_text("", encoding="utf-8")
    base = {
        "AUTOSOC_SPLUNK_URL": "https://localhost:8089",
        "AUTOSOC_SPLUNK_USERNAME": "svc",
        "AUTOSOC_SPLUNK_PASSWORD": "secret-value",
        "AUTOSOC_SPLUNK_INDEX": INDEX,
    }
    for name in ("AUTOSOC_SPLUNK_VERIFY_TLS", "AUTOSOC_SPLUNK_CA_CERT", "AUTOSOC_SPLUNK_ALLOW_INSECURE_HTTP"):
        monkeypatch.delenv(name, raising=False)
    for name, value in {**base, **values}.items():
        monkeypatch.setenv(name, value)
    return env_file


def test_live_composition_requires_tls_verification(monkeypatch, tmp_path):
    env_file = _splunk_env(monkeypatch, tmp_path, AUTOSOC_SPLUNK_VERIFY_TLS="false")
    with pytest.raises(ValueError, match="AUTOSOC_SPLUNK_VERIFY_TLS must stay enabled") as error:
        platform_module.build_splunk_platform_service(
            edit_constraints=EDIT_CONSTRAINTS, env_file=env_file, evidence_dir=tmp_path / "e"
        )
    assert "secret-value" not in str(error.value)

    env_file = _splunk_env(monkeypatch, tmp_path, AUTOSOC_SPLUNK_CA_CERT=str(tmp_path / "missing.pem"))
    with pytest.raises(ValueError, match="AUTOSOC_SPLUNK_CA_CERT"):
        platform_module.build_splunk_platform_service(
            edit_constraints=EDIT_CONSTRAINTS, env_file=env_file, evidence_dir=tmp_path / "e"
        )

    env_file = _splunk_env(
        monkeypatch, tmp_path, AUTOSOC_SPLUNK_URL="http://localhost:8089",
        AUTOSOC_SPLUNK_ALLOW_INSECURE_HTTP="true",
    )
    with pytest.raises(ValueError, match="HTTPS"):
        platform_module.build_splunk_platform_service(
            edit_constraints=EDIT_CONSTRAINTS, env_file=env_file, evidence_dir=tmp_path / "e"
        )


def test_live_composition_accepts_a_configured_ca(monkeypatch, tmp_path):
    certifi = pytest.importorskip("certifi")  # any valid PEM bundle stands in for the Splunk CA
    env_file = _splunk_env(monkeypatch, tmp_path, AUTOSOC_SPLUNK_CA_CERT=certifi.where())
    platform = platform_module.build_splunk_platform_service(
        edit_constraints=EDIT_CONSTRAINTS, env_file=env_file, evidence_dir=tmp_path / "e"
    )
    assert isinstance(platform, platform_module.SplunkPlatformService)


# ------------------------------------------------------------ end to end


def _assembled_services(platform):
    from shared_services.controller.services import WorkflowComponentAdapter

    red = runner._load_adapter("red_service")
    blue = runner._load_adapter("blue_service")
    judge = runner._load_adapter("judge_service")
    calls = {"blue": 0, "judge": 0}

    class Counting:
        def __init__(self, inner, name):
            self.inner, self.name = inner, name

        def run(self, payload):
            calls[self.name] += 1
            return self.inner.run(payload)

    services = runner.SimpleNamespace(
        red=WorkflowComponentAdapter(red.build_red_service(provider="mock"), "red_proposal"),
        blue=Counting(WorkflowComponentAdapter(blue.build_blue_service(provider="none"), "blue_proposal"), "blue"),
        platform=platform,
        judge=Counting(WorkflowComponentAdapter(judge.build_judge_service(), "judge_result"), "judge"),
    )
    return services, calls


@pytest.fixture
def mongo_repo(monkeypatch):
    mongomock = pytest.importorskip("mongomock")
    import shared_services.datastore.repository as repository_module
    from shared_services.datastore.repository import MongoRepository

    monkeypatch.setattr(repository_module, "MongoClient", mongomock.MongoClient)
    repo = MongoRepository(db_name=f"autosoc_test_{uuid4().hex}")
    yield repo
    repo.close()


def test_orchestrated_round_reaches_the_judge_with_measured_evidence(make_platform, mongo_repo, server, operator):
    from shared_services.controller.round_controller import RoundController

    services, calls = _assembled_services(make_platform())
    task_id = f"assembled-test-{uuid4().hex}"
    outcome = RoundController(mongo_repo, services).run_round(round_request(task_id))

    assert outcome.state == "completed", getattr(outcome.record, "error", None)
    assert calls == {"blue": 1, "judge": 1}
    judge = mongo_repo.find_by_task("judge_result", task_id)[-1]
    assert judge["decision"]["status"] == "PASS"
    assert [s["search"][0].split(" ")[0] for s in server.searches] == ["search"] * 3
    assert len(operator.prompts) == 3
    candidate_rule = mongo_repo.find_by_task("candidate_rule", task_id)[-1]
    assert server.searches[-1]["search"] == [candidate_rule["compiled_rule"]["text"]]


def test_orchestrated_round_stops_before_blue_and_judge_on_unreviewed_labels(
    make_platform, mongo_repo, tmp_path, server, operator
):
    from shared_services.controller.round_controller import RoundController

    platform = make_platform()
    write_labels(tmp_path / "prepared", label_set(reviewed=False))
    services, calls = _assembled_services(platform)
    task_id = f"assembled-test-{uuid4().hex}"
    outcome = RoundController(mongo_repo, services).run_round(round_request(task_id))

    assert outcome.state not in {"completed", "judged"}
    assert calls == {"blue": 0, "judge": 0}
    assert server.searches == [] and operator.prompts == []
    assert not mongo_repo.find_by_task("judge_result", task_id)
    assert "telemetry_evidence" not in outcome.record.artifacts
    error = outcome.record.error
    assert error["category"] == "missing_information"
    assert "not judge-ready" in error["message"]


def test_live_shaped_export_without_fields_reaches_the_judge(make_platform, lab, mongo_repo, tmp_path, server):
    """Splunk returns _raw and default fields only, as the live export did."""
    from shared_services.controller.round_controller import RoundController

    raw = {symbol: json.dumps(EVENTS[symbol][1], sort_keys=True) for symbol in EVENT_IDS}
    stable = {symbol: stable_event_id(text) for symbol, text in raw.items()}
    dataset = {**DATASET, "evaluation_set_checksum": evaluation_set_checksum(stable.values())}
    labels = label_set()
    labels["dataset"] = dict(dataset)
    for label in labels["labels"]:
        label["event_id"] = stable[label["event_id"]]
    write_labels(tmp_path / "prepared", labels)

    full = {symbol: {**splunk_record(symbol), "_raw": raw[symbol]} for symbol in EVENT_IDS}
    lab.records = full
    default_only = ("_time", "_cd", "_raw", "_bkt", "index", "autosoc_eval_set", "host", "source", "sourcetype")
    evaluate = lab.__call__
    server.responder = lambda params: [
        {key: record[key] for key in default_only} for record in evaluate(params)
    ]

    platform = make_platform(event_normalizer=normalize_frozen_set_event)
    services, calls = _assembled_services(platform)
    task_id = f"assembled-test-{uuid4().hex}"
    request = round_request(task_id)
    request["dataset"] = dataset
    outcome = RoundController(mongo_repo, services).run_round(request)

    assert outcome.state == "completed", getattr(outcome.record, "error", None)
    assert calls == {"blue": 1, "judge": 1}
    assert mongo_repo.find_by_task("judge_result", task_id)[-1]["decision"]["status"] == "PASS"
    telemetry = mongo_repo.find_by_task("telemetry_evidence", task_id)[-1]
    assert {event["event_id"] for event in telemetry["events"]} == set(stable.values())
    assert all("User" in event["fields"] for event in telemetry["events"])
    baseline = mongo_repo.find_by_task("match_set", task_id)
    assert {m["event_id"] for m in baseline[0]["matches"]} <= set(stable.values())
