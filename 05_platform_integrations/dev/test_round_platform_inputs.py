"""Bound search approvals, judge-ready label checks, and event-level rule projection."""

from __future__ import annotations

import copy
import json
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

from dev.mocks.splunk.server import create_server
from evidence_store.store import EvidenceStore
from proposal_execution import ProposalExecutionService
from splunk_execution import ApprovedSearchRequest, ManualCLIApprovalAuthorizer, SplunkClient, SplunkConfig
from splunk_execution.approval import bound_approval_id
from validation.labels import (
    LabelSetNotReady,
    evaluation_set_checksum,
    load_prepared_label_set,
    require_frozen_dataset,
    require_judge_ready_label_set,
)
from validation.rule_compiler import (
    BaseRule,
    compile_candidate_rule,
    event_level_search,
    render_base_rule,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = REPO_ROOT / "00_shared_contracts"
EVENT_IDS = ["evt-a", "evt-b", "evt-c"]
DATASET = {
    "dataset_id": "lab-sysmon",
    "dataset_version": "2026.11.1",
    "evaluation_set_id": "evalset-test-v1",
    "evaluation_set_checksum": evaluation_set_checksum(EVENT_IDS),
}


def bound_request(**changes) -> ApprovedSearchRequest:
    request = ApprovedSearchRequest(
        task_id="task-1",
        task_version="rr-1",
        operation_id="task-1:telemetry",
        approval_id="pending",
        spl="search index=lab_eval autosoc_eval_set::evalset-test-v1",
        earliest_time="0",
        latest_time="now",
        proposal_id="proposal-1",
        dataset=dict(DATASET),
    )
    request = replace(request, approval_id=bound_approval_id(request, "lab_eval"))
    return replace(request, **changes) if changes else request


def reviewed_label_set() -> dict:
    return {
        "contract_version": "0.1.0",
        "label_set_id": "labels-test",
        "label_set_version": "1",
        "dataset": dict(DATASET),
        "coverage": {"total_events": 3, "complete": True},
        "labels": [
            {
                "event_id": event_id,
                "label": "attack" if event_id == "evt-a" else "benign",
                "source": "public_dataset",
                "review": {
                    "status": "reviewed",
                    "reviewer": "analyst-1",
                    "reviewed_at": "2026-11-10T09:00:00Z",
                },
            }
            for event_id in EVENT_IDS
        ],
    }


class BoundApprovalTests(unittest.TestCase):
    def approver(self, prompts: list[str], answer: str | None = None):
        def confirm(prompt: str) -> str:
            prompts.append(prompt)
            if answer is not None:
                return answer
            reference = next(
                line.split(": ", 1)[1]
                for line in prompt.splitlines()
                if line.startswith("Approval reference: ")
            )
            return f"APPROVE {reference}"

        return confirm

    def test_bound_request_is_approved_after_showing_every_binding(self) -> None:
        prompts: list[str] = []
        authorizer = ManualCLIApprovalAuthorizer(
            "lab_eval", require_binding=True, confirm=self.approver(prompts)
        )
        request = bound_request()
        self.assertTrue(authorizer.is_approved(request))
        prompt = prompts[0]
        for expected in (
            "Proposal: proposal-1",
            "evaluation_set_id=evalset-test-v1",
            f"evaluation_set_checksum={DATASET['evaluation_set_checksum']}",
            "dataset_version=2026.11.1",
            "Index scope: lab_eval",
            "Time range: 0 to now",
            f"SPL: {request.spl}",
        ):
            self.assertIn(expected, prompt)

    def test_wrong_confirmation_is_rejected(self) -> None:
        authorizer = ManualCLIApprovalAuthorizer(
            "lab_eval", require_binding=True, confirm=self.approver([], "APPROVE something-else")
        )
        self.assertFalse(authorizer.is_approved(bound_request()))

    def test_requests_altered_after_binding_are_refused_without_prompting(self) -> None:
        authorizer = ManualCLIApprovalAuthorizer(
            "lab_eval",
            require_binding=True,
            confirm=lambda prompt: self.fail(f"altered request must not prompt: {prompt}"),
        )
        original = bound_request()
        altered = {
            "spl": replace(original, spl=original.spl + " EventID=8"),
            "task": replace(original, task_id="task-2"),
            "task_version": replace(original, task_version="rr-2"),
            "operation": replace(original, operation_id="task-1:candidate"),
            "proposal": replace(original, proposal_id="proposal-2"),
            "dataset_version": replace(
                original, dataset={**DATASET, "dataset_version": "2026.12.0"}
            ),
            "checksum": replace(
                original, dataset={**DATASET, "evaluation_set_checksum": "0" * 64}
            ),
            "earliest": replace(original, earliest_time="-24h"),
            "latest": replace(original, latest_time="-1h"),
            "unbound_id": replace(original, approval_id="approval-9"),
        }
        for name, request in altered.items():
            with self.subTest(name):
                self.assertFalse(authorizer.is_approved(request))

    def test_approval_for_one_index_scope_does_not_cover_another(self) -> None:
        request = bound_request()
        other = ManualCLIApprovalAuthorizer(
            "lab_eval_2",
            require_binding=True,
            confirm=lambda prompt: self.fail("out-of-scope search must not prompt"),
        )
        self.assertFalse(other.is_approved(replace(request, spl="search index=lab_eval_2")))
        self.assertNotEqual(bound_approval_id(request, "lab_eval"), bound_approval_id(request, "lab_eval_2"))

    def test_malformed_bound_requests_are_refused(self) -> None:
        authorizer = ManualCLIApprovalAuthorizer(
            "lab_eval",
            require_binding=True,
            confirm=lambda prompt: self.fail("malformed request must not prompt"),
        )
        base = bound_request()
        without_proposal = replace(base, proposal_id=None)
        without_dataset = replace(base, dataset=None)
        without_checksum_dataset = {k: v for k, v in DATASET.items() if k != "evaluation_set_checksum"}
        without_checksum = replace(base, dataset=without_checksum_dataset)
        cases = {
            "no proposal": replace(
                without_proposal, approval_id=bound_approval_id(without_proposal, "lab_eval")
            ),
            "no dataset": replace(
                without_dataset, approval_id=bound_approval_id(without_dataset, "lab_eval")
            ),
            "no checksum": replace(
                without_checksum, approval_id=bound_approval_id(without_checksum, "lab_eval")
            ),
            "other index": replace(base, spl="search index=production"),
            "pipeline": replace(base, spl=base.spl + " | delete"),
            "macro": replace(base, spl=base.spl + " `sysmon`"),
            "non-printable proposal": replace(base, proposal_id="proposal\u200b"),
        }
        for name, request in cases.items():
            with self.subTest(name):
                self.assertFalse(authorizer.is_approved(request))
        with self.assertRaises(ValueError):
            replace(base, dataset={**DATASET, "evaluation_set_checksum": "not-a-sha"})


class LabelReadinessTests(unittest.TestCase):
    def test_complete_reviewed_set_frozen_to_the_dataset_is_accepted(self) -> None:
        labels = reviewed_label_set()
        snapshot = copy.deepcopy(labels)
        self.assertIs(require_judge_ready_label_set(labels, DATASET), labels)
        self.assertEqual(labels, snapshot)

    def assert_not_ready(self, labels: dict, message: str, dataset: dict = DATASET) -> None:
        snapshot = copy.deepcopy(labels)
        with self.assertRaisesRegex(LabelSetNotReady, message):
            require_judge_ready_label_set(labels, dataset)
        self.assertEqual(labels, snapshot, "rejected labels must not be modified")

    def test_unreviewed_and_incomplete_sets_are_rejected_without_promotion(self) -> None:
        labels = reviewed_label_set()
        labels["coverage"]["complete"] = False
        for label in labels["labels"]:
            label["review"] = {"status": "unreviewed"}
        self.assert_not_ready(labels, r"coverage.complete is false; 3 of 3 labels are not reviewed")

    def test_disputed_label_is_rejected(self) -> None:
        labels = reviewed_label_set()
        labels["coverage"]["complete"] = False
        labels["labels"][1]["review"] = {"status": "disputed", "reviewer": "analyst-2"}
        self.assert_not_ready(labels, "1 of 3 labels are not reviewed")

    def test_partial_coverage_is_rejected(self) -> None:
        labels = reviewed_label_set()
        labels["coverage"]["total_events"] = 4
        self.assert_not_ready(labels, "LS-2")

    def test_reviewed_labels_require_reviewer_attribution(self) -> None:
        labels = reviewed_label_set()
        del labels["labels"][0]["review"]["reviewer"]
        self.assert_not_ready(labels, "no reviewer attribution")

    def test_dataset_identity_must_match_the_frozen_round(self) -> None:
        for field, value in (
            ("dataset_id", "other"),
            ("dataset_version", "2026.12.0"),
            ("evaluation_set_id", "evalset-other"),
            ("evaluation_set_checksum", "f" * 64),
        ):
            with self.subTest(field):
                labels = reviewed_label_set()
                labels["dataset"][field] = value
                self.assert_not_ready(labels, f"dataset.{field}")

    def test_label_ids_must_hash_to_the_frozen_checksum(self) -> None:
        labels = reviewed_label_set()
        labels["labels"][2]["event_id"] = "evt-z"
        self.assert_not_ready(labels, "do not hash to the frozen evaluation_set_checksum")

    def test_duplicate_ids_and_malformed_sets_are_rejected(self) -> None:
        labels = reviewed_label_set()
        labels["labels"][2]["event_id"] = "evt-a"
        self.assert_not_ready(labels, "LS-1")
        malformed = reviewed_label_set()
        malformed["labels"][0]["label"] = "probably-bad"
        self.assert_not_ready(malformed, "malformed")

    def test_round_dataset_requires_every_frozen_identity_field(self) -> None:
        with self.assertRaisesRegex(LabelSetNotReady, "evaluation_set_checksum"):
            require_frozen_dataset({k: v for k, v in DATASET.items() if k != "evaluation_set_checksum"})
        with self.assertRaisesRegex(LabelSetNotReady, "evaluation_set_id"):
            require_frozen_dataset({**DATASET, "evaluation_set_id": "../escape"})

    def test_prepared_label_loader_reports_missing_and_malformed_files(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(LabelSetNotReady, "not found"):
                load_prepared_label_set(root, "evalset-test-v1")
            path = Path(root) / "evalset-test-v1" / "labels"
            path.mkdir(parents=True)
            (path / "reviewed_label_set.json").write_text('{"labels": [', encoding="utf-8")
            with self.assertRaisesRegex(LabelSetNotReady, "malformed"):
                load_prepared_label_set(root, "evalset-test-v1")
            with self.assertRaisesRegex(LabelSetNotReady, "safe directory"):
                load_prepared_label_set(root, "../evalset-test-v1")

    def test_local_demo_set_is_not_judge_ready(self) -> None:
        prepared = REPO_ROOT / "05_platform_integrations" / "labelled_data" / "public_datasets" / "prepared"
        if not (prepared / "evalset-demo-lsass-v1").is_dir():
            self.skipTest("prepared demo set is not available (git-ignored)")
        labels = load_prepared_label_set(prepared, "evalset-demo-lsass-v1")
        with self.assertRaisesRegex(LabelSetNotReady, "not reviewed"):
            require_judge_ready_label_set(labels, labels["dataset"])


class EventLevelProjectionTests(unittest.TestCase):
    LSASS = (
        "(source=WinEventLog:Microsoft-Windows-Sysmon/Operational OR "
        "source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational)\nEventID=8\n"
        'TargetImage="*\\\\lsass.exe"\n'
        "| stats count min(_time) as firstTime\n"
        '              values(NewThreadId) as "NewThreadId"\n'
        "  by dest signature_id SourceImage\n"
        '| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)\n'
        "| search *"
    )

    def test_stats_by_fields_become_presence_filters(self) -> None:
        self.assertEqual(
            event_level_search(self.LSASS),
            "((source=WinEventLog:Microsoft-Windows-Sysmon/Operational OR "
            "source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational) EventID=8 "
            'TargetImage="*\\\\lsass.exe") dest=* signature_id=* SourceImage=*',
        )

    def test_plain_search_is_grouped_without_changes(self) -> None:
        self.assertEqual(
            event_level_search('search Image="*\\\\powershell.exe"'),
            '(Image="*\\\\powershell.exe")',
        )

    def test_tails_that_filter_aggregates_are_rejected(self) -> None:
        for rule in (
            "EventID=8 | stats count by host | search count>5",
            "EventID=8 | where count>5",
            "EventID=8 | stats count by host | stats count by dest",
            "EventID=8 | search * | convert ctime(x)",
        ):
            with self.subTest(rule):
                with self.assertRaises(ValueError):
                    event_level_search(rule)

    def test_search_prefixed_template_keeps_valid_spl_after_exclusions(self) -> None:
        proposal = json.loads(
            (CONTRACTS / "blue_proposal" / "examples" / "valid_blue_proposal.json").read_text(
                encoding="utf-8"
            )
        )
        base = BaseRule(
            task_id=proposal["task_id"],
            detection_id="win-encoded-powershell",
            rule_version="3.2.0",
            spl_template='search index=lab_eval autosoc_eval_set::evalset-test-v1 (Image="*\\\\powershell.exe")',
            selections={},
        )
        rendered = render_base_rule(base)
        compiled = compile_candidate_rule(proposal, base, candidate_rule_version="c1")["compiled_rule"]["text"]
        self.assertEqual(
            rendered,
            'search index=lab_eval autosoc_eval_set::evalset-test-v1 (Image="*\\\\powershell.exe")',
        )
        self.assertTrue(compiled.startswith("search (index=lab_eval autosoc_eval_set::evalset-test-v1 "))
        self.assertIn(") NOT (", compiled)
        self.assertNotIn("(search", compiled)


class BaselineExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_server()
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self) -> None:
        self.server.response_mode = "success"
        self.server.last_search = None
        self.temp = tempfile.TemporaryDirectory()
        self.service = ProposalExecutionService(
            SplunkClient(
                SplunkConfig(
                    base_url=f"http://127.0.0.1:{self.server.server_port}",
                    username="test-user",
                    password="test-password",
                    allow_insecure_http=True,
                ),
                ManualCLIApprovalAuthorizer(
                    "lab_eval",
                    require_binding=True,
                    confirm=lambda prompt: "APPROVE " + next(
                        line.split(": ", 1)[1]
                        for line in prompt.splitlines()
                        if line.startswith("Approval reference: ")
                    ),
                ),
            ),
            EvidenceStore(self.temp.name),
        )
        self.base = BaseRule(
            task_id="task-1",
            detection_id="det-1",
            rule_version="1",
            spl_template="search index=lab_eval autosoc_eval_set::evalset-test-v1 (EventID=8)",
            selections={},
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def baseline_request(self, spl: str | None = None) -> ApprovedSearchRequest:
        return bound_request(
            operation_id="task-1:baseline",
            spl=spl or render_base_rule(self.base),
        )

    def rebind(self, request: ApprovedSearchRequest) -> ApprovedSearchRequest:
        return replace(request, approval_id=bound_approval_id(request, "lab_eval"))

    def test_baseline_match_set_is_measured_and_persisted(self) -> None:
        request = self.rebind(self.baseline_request())
        result = self.service.run_baseline_rule(
            self.base, proposal_id="proposal-1", approved_search=request, dataset=DATASET
        )
        match_set = result.match_set
        self.assertEqual(match_set["role"], "baseline")
        self.assertNotIn("candidate_ref", match_set)
        self.assertEqual(match_set["rule_version"], "1")
        self.assertEqual(match_set["dataset"], DATASET)
        self.assertEqual(match_set["execution"]["status"], "completed")
        self.assertEqual(match_set["execution"]["search_ref"], "task-1:baseline")
        stored = EvidenceStore(self.temp.name).get(match_set["evidence_reference"]["evidence_id"])
        self.assertEqual(stored["execution"]["approval_id"], request.approval_id)
        self.assertEqual(self.server.last_search["search"], [render_base_rule(self.base)])

    def test_display_formatted_times_are_omitted_from_matches_not_fatal(self) -> None:
        events = [
            {"_time": "2026-11-21 09:03:11.920 Egypt Standard Time", "event_id": "evt-a", "_raw": "a"},
            {"_time": "2026-11-21T09:03:11.920+02:00", "event_id": "evt-b", "_raw": "b"},
        ]
        self.server.responder = lambda _params: events
        try:
            result = self.service.run_baseline_rule(
                self.base, proposal_id="proposal-1",
                approved_search=self.rebind(self.baseline_request()), dataset=DATASET,
            )
        finally:
            self.server.responder = None
        matches = {m["event_id"]: m for m in result.match_set["matches"]}
        self.assertNotIn("event_time", matches["evt-a"])
        self.assertEqual(matches["evt-b"]["event_time"], "2026-11-21T09:03:11.920+02:00")
        stored = EvidenceStore(self.temp.name).get(result.match_set["evidence_reference"]["evidence_id"])
        self.assertEqual(
            {e["event_id"]: e["timestamp"] for e in stored["events"]}["evt-a"],
            "2026-11-21 09:03:11.920 Egypt Standard Time",
        )

    def test_baseline_approval_must_cover_the_rendered_rule_and_dataset(self) -> None:
        with self.assertRaisesRegex(ValueError, "rendered base rule"):
            self.service.run_baseline_rule(
                self.base,
                proposal_id="proposal-1",
                approved_search=self.rebind(self.baseline_request("search index=lab_eval")),
                dataset=DATASET,
            )
        with self.assertRaisesRegex(ValueError, "frozen evaluation set"):
            self.service.run_baseline_rule(
                self.base,
                proposal_id="proposal-1",
                approved_search=self.rebind(self.baseline_request()),
                dataset={**DATASET, "dataset_version": "other"},
            )
        with self.assertRaisesRegex(ValueError, "proposal_id"):
            self.service.run_baseline_rule(
                self.base,
                proposal_id="proposal-2",
                approved_search=self.rebind(self.baseline_request()),
                dataset=DATASET,
            )
        self.assertIsNone(self.server.last_search)


if __name__ == "__main__":
    unittest.main()
