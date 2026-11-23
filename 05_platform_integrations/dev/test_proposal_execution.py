from __future__ import annotations

import json
import hashlib
import tempfile
import threading
import unittest
from pathlib import Path

from dev.mocks.splunk.server import EVENTS, create_server
from evidence_store.store import EvidenceStore, EvidenceStoreError
from proposal_execution import ProposalExecutionService
from splunk_execution import (
    ApprovedSearchRequest,
    SplunkApprovalError,
    SplunkClient,
    SplunkConfig,
)
from validation.proposals import ContractValidationError
from validation.rule_compiler import BaseRule, compile_candidate_rule


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = REPO_ROOT / "00_shared_contracts"


class TestAuthorizer:
    def __init__(self, approved: bool = True) -> None:
        self.approved = approved
        self.requests: list[ApprovedSearchRequest] = []

    def is_approved(self, request: ApprovedSearchRequest) -> bool:
        self.requests.append(request)
        return self.approved


class ProposalExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_server()
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self) -> None:
        self.server.response_mode = "success"
        self.server.last_search = None
        self.temp_dir = tempfile.TemporaryDirectory()
        self.authorizer = TestAuthorizer()
        self.service = ProposalExecutionService(
            SplunkClient(
                SplunkConfig(
                    base_url=self.base_url,
                    username="test-user",
                    password="test-password",
                    allow_insecure_http=True,
                ),
                self.authorizer,
            ),
            EvidenceStore(self.temp_dir.name),
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @staticmethod
    def fixture(path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def red_proposal(self) -> dict:
        return self.fixture(
            CONTRACTS / "red_proposal" / "examples" / "valid_red_proposal.json"
        )

    def blue_proposal(self) -> dict:
        return self.fixture(
            CONTRACTS / "blue_proposal" / "examples" / "valid_blue_proposal.json"
        )

    @staticmethod
    def search(
        spl: str,
        task_id: str = "round-2026-11-17-001",
        proposal_id: str | None = None,
        dataset: dict | None = None,
    ) -> ApprovedSearchRequest:
        return ApprovedSearchRequest(
            task_id=task_id,
            task_version="1",
            operation_id="approved-operation-1",
            approval_id="approval-1",
            spl=spl,
            proposal_id=proposal_id,
            dataset=dataset,
        )

    def test_red_proposal_returns_persisted_contract_valid_telemetry(self) -> None:
        result = self.service.run_red_proposal(
            self.red_proposal(),
            self.search(
                "search index=lab_eval",
                proposal_id=self.red_proposal()["proposal_id"],
            ),
        )
        evidence = result.telemetry_evidence

        self.assertEqual(evidence["proposal_id"], self.red_proposal()["proposal_id"])
        self.assertEqual(evidence["execution"]["status"], "succeeded")
        self.assertEqual(evidence["events"][0]["event_id"], "0:123")
        self.assertEqual(result.evidence_reference["evidence_type"], "telemetry")
        stored = EvidenceStore(self.temp_dir.name).get(evidence["evidence_id"])
        self.assertEqual(stored, evidence)
        self.assertEqual(
            self.server.last_search["search"], ["search index=lab_eval"]
        )

    def test_persisted_evidence_is_immutable_and_integrity_checked(self) -> None:
        result = self.service.run_red_proposal(
            self.red_proposal(),
            self.search(
                "search index=lab_eval",
                proposal_id=self.red_proposal()["proposal_id"],
            ),
        )
        evidence = result.telemetry_evidence
        store = EvidenceStore(self.temp_dir.name)

        with self.assertRaisesRegex(EvidenceStoreError, "already exists"):
            store.put({key: value for key, value in evidence.items() if key != "content_sha256"})
        path = Path(self.temp_dir.name) / f"{evidence['evidence_id']}.json"
        tampered = dict(evidence)
        tampered["task_id"] = "tampered"
        path.write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceStoreError, "integrity"):
            store.get(evidence["evidence_id"])

    def test_invalid_red_proposal_is_rejected_before_authorization_or_execution(self) -> None:
        proposal = self.red_proposal()
        proposal["unexpected"] = True

        with self.assertRaises(ContractValidationError):
            self.service.run_red_proposal(
                proposal,
                self.search("search index=lab_eval", proposal_id=proposal["proposal_id"]),
            )

        self.assertEqual(self.authorizer.requests, [])
        self.assertIsNone(self.server.last_search)

    def test_unapproved_red_search_is_not_executed(self) -> None:
        self.authorizer.approved = False

        with self.assertRaisesRegex(SplunkApprovalError, "not approved"):
            self.service.run_red_proposal(
                self.red_proposal(),
                self.search(
                    "search index=lab_eval",
                    proposal_id=self.red_proposal()["proposal_id"],
                ),
            )

        self.assertIsNone(self.server.last_search)

    def test_red_search_must_be_bound_to_the_proposal(self) -> None:
        with self.assertRaisesRegex(ValueError, "proposal_id does not match"):
            self.service.run_red_proposal(
                self.red_proposal(), self.search("search index=lab_eval")
            )

        self.assertEqual(self.authorizer.requests, [])
        self.assertIsNone(self.server.last_search)

    def test_blue_proposal_compiles_executes_and_returns_candidate_match_set(self) -> None:
        proposal = self.blue_proposal()
        base_rule = BaseRule(
            task_id=proposal["task_id"],
            detection_id="win-encoded-powershell",
            rule_version="3.2.0",
            spl_template=(
                "index=lab_eval sourcetype=XmlWinEventLog "
                "Image=*powershell.exe CommandLine=*-enc*"
            ),
            selections={},
        )
        candidate = compile_candidate_rule(
            proposal, base_rule, candidate_rule_version="3.2.1-candidate-1"
        )
        result = self.service.run_blue_proposal(
            proposal,
            base_rule,
            candidate_rule_version="3.2.1-candidate-1",
            approved_search=self.search(
                candidate["compiled_rule"]["text"],
                task_id=proposal["task_id"],
                proposal_id=proposal["proposal_id"],
                dataset={
                    "dataset_id": "lab-sysmon",
                    "dataset_version": "2026.11.1",
                    "evaluation_set_id": "evalset-01",
                },
            ),
            dataset={
                "dataset_id": "lab-sysmon",
                "dataset_version": "2026.11.1",
                "evaluation_set_id": "evalset-01",
            },
        )

        self.assertEqual(result.candidate_rule["candidate_rule_version"], "3.2.1-candidate-1")
        self.assertIn("permissions", result.candidate_rule["validation"]["checks"])
        self.assertEqual(result.match_set["role"], "candidate")
        self.assertEqual(result.match_set["candidate_ref"], result.candidate_rule["candidate_id"])
        self.assertEqual(result.match_set["execution"]["status"], "completed")
        second_event_id = hashlib.sha256(
            json.dumps(EVENTS[1], sort_keys=True, separators=(",", ":"), default=str).encode(
                "utf-8"
            )
        ).hexdigest()
        self.assertEqual(
            [item["event_id"] for item in result.match_set["matches"]],
            ["0:123", second_event_id],
        )

    def test_blue_approval_must_cover_exact_compiled_search(self) -> None:
        proposal = self.blue_proposal()
        base_rule = BaseRule(
            task_id=proposal["task_id"],
            detection_id="win-encoded-powershell",
            rule_version="3.2.0",
            spl_template="index=lab_eval Image=*powershell.exe",
            selections={},
        )

        with self.assertRaisesRegex(ValueError, "does not exactly match"):
            self.service.run_blue_proposal(
                proposal,
                base_rule,
                candidate_rule_version="3.2.1-candidate-1",
                approved_search=self.search(
                    "search index=lab_eval",
                    task_id=proposal["task_id"],
                    proposal_id=proposal["proposal_id"],
                    dataset={
                        "dataset_id": "lab-sysmon",
                        "dataset_version": "2026.11.1",
                        "evaluation_set_id": "evalset-01",
                    },
                ),
                dataset={
                    "dataset_id": "lab-sysmon",
                    "dataset_version": "2026.11.1",
                    "evaluation_set_id": "evalset-01",
                },
            )

        self.assertEqual(self.authorizer.requests, [])
        self.assertIsNone(self.server.last_search)

    def test_blue_approval_must_bind_the_frozen_dataset(self) -> None:
        proposal = self.blue_proposal()
        base_rule = BaseRule(
            task_id=proposal["task_id"],
            detection_id="win-encoded-powershell",
            rule_version="3.2.0",
            spl_template="index=lab_eval Image=*powershell.exe",
            selections={},
        )
        dataset = {
            "dataset_id": "lab-sysmon",
            "dataset_version": "2026.11.1",
            "evaluation_set_id": "evalset-01",
        }

        with self.assertRaisesRegex(ValueError, "does not match the frozen evaluation set"):
            self.service.run_blue_proposal(
                proposal,
                base_rule,
                candidate_rule_version="3.2.1-candidate-1",
                approved_search=self.search(
                    compile_candidate_rule(
                        proposal, base_rule, candidate_rule_version="3.2.1-candidate-1"
                    )["compiled_rule"]["text"],
                    task_id=proposal["task_id"],
                    proposal_id=proposal["proposal_id"],
                    dataset={**dataset, "evaluation_set_id": "other-set"},
                ),
                dataset=dataset,
            )

        self.assertEqual(self.authorizer.requests, [])
        self.assertIsNone(self.server.last_search)

    def test_narrow_selection_requires_and_updates_named_base_selection(self) -> None:
        proposal = self.blue_proposal()
        proposal["edits"][0] = {
            "operation": "narrow_selection",
            "target_selection": "process",
            "conditions": [
                {"field": "User", "modifier": "equals", "values": ["CORP\\svc_inventory"]}
            ],
            "reason": "Scope the process selection.",
        }
        base_rule = BaseRule(
            task_id=proposal["task_id"],
            detection_id="win-encoded-powershell",
            rule_version="3.2.0",
            spl_template="index=lab_eval {{process}}",
            selections={"process": "Image=*powershell.exe"},
        )

        candidate = compile_candidate_rule(
            proposal, base_rule, candidate_rule_version="3.2.1"
        )

        self.assertIn('User="CORP\\\\svc_inventory"', candidate["compiled_rule"]["text"])
        with self.assertRaisesRegex(ValueError, "not present in the base rule"):
            compile_candidate_rule(
                proposal,
                BaseRule(
                    task_id=proposal["task_id"],
                    detection_id="win-encoded-powershell",
                    rule_version="3.2.0",
                    spl_template="index=lab_eval Image=*powershell.exe",
                    selections={},
                ),
                candidate_rule_version="3.2.1",
            )


if __name__ == "__main__":
    unittest.main()
