"""Public interface adapters are wired to RoundManager and artifact storage."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from orchestrator_interfaces import ArtifactPersistenceError, InMemoryArtifactStore
from orchestrator_interfaces.inputs.adapter import ComponentFailure, OrchestratorInputAdapter
from orchestrator_interfaces.outputs.adapter import ContractAlignmentError, OrchestratorOutputAdapter
from orchestrator_interfaces.outputs.cross_contract import validate_judge_evidence
from round_management import InMemoryRoundStore, RoundManager, RoundState


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT.parent / "00_shared_contracts"


class PassthroughValidator:
    """Keeps these wiring tests runnable without the optional schema package."""

    def validate(self, _contract, message):
        return json.loads(json.dumps(message, allow_nan=False))


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def request() -> dict:
    return load_json(CONTRACTS / "round_request/examples/valid_round_request.json")


def manager_and_adapters():
    artifacts = InMemoryArtifactStore()
    manager = RoundManager(InMemoryRoundStore())
    validator = PassthroughValidator()
    return manager, artifacts, OrchestratorInputAdapter(manager, artifacts, validator), OrchestratorOutputAdapter(manager, artifacts, validator)


class InputAdapterTests(unittest.TestCase):
    def test_open_round_saves_request_once_and_same_request_retry_reuses_it(self):
        manager, artifacts, inputs, _outputs = manager_and_adapters()
        req = request()

        first = inputs.open_round(req)
        second = inputs.open_round(req)

        self.assertEqual(first.round_id, second.round_id)
        self.assertEqual(len(artifacts.find_by_task("round_request", req["task_id"])), 1)

    def test_partial_artifact_write_retry_reuses_the_successful_first_write(self):
        class FailOnceStore(InMemoryArtifactStore):
            def __init__(self):
                super().__init__()
                self.fail_reviewed_labels = True

            def save(self, contract, payload):
                if contract == "reviewed_label_set" and self.fail_reviewed_labels:
                    self.fail_reviewed_labels = False
                    raise RuntimeError("simulated storage interruption")
                return super().save(contract, payload)

        artifacts = FailOnceStore()
        manager = RoundManager(InMemoryRoundStore())
        validator = PassthroughValidator()
        inputs = OrchestratorInputAdapter(manager, artifacts, validator)
        req = request()
        round_id = req["task_id"]
        inputs.open_round(req)
        manager.advance(round_id, RoundState.RED_PROPOSED, artifacts={"red_proposal": "memory://red/1"})
        manager.advance(round_id, RoundState.TELEMETRY_COLLECTED)
        inputs.begin_attempt(round_id)
        messages = {
            "telemetry_evidence": {"task_id": round_id},
            "reviewed_label_set": {"task_id": round_id},
            "baseline_match_set": {"task_id": round_id, "role": "baseline"},
        }

        with self.assertRaisesRegex(ArtifactPersistenceError, "simulated storage interruption"):
            inputs.accept_step_result(round_id, RoundState.EVIDENCE_VERIFIED, messages)
        accepted = inputs.accept_step_result(round_id, RoundState.EVIDENCE_VERIFIED, messages)

        self.assertEqual(accepted.state, RoundState.EVIDENCE_VERIFIED)
        self.assertEqual(len(artifacts.find_by_task("telemetry_evidence", round_id)), 1)

    def test_step_output_is_persisted_and_attached_to_the_manager_transition(self):
        manager, artifacts, inputs, _outputs = manager_and_adapters()
        req = request()
        round_id = req["task_id"]
        inputs.open_round(req)
        proposal = load_json(CONTRACTS / "red_proposal/examples/valid_red_proposal.json")
        proposal["task_id"] = round_id

        inputs.begin_attempt(round_id)
        record = inputs.accept_step_result(round_id, RoundState.RED_PROPOSED, {"red_proposal": proposal})

        self.assertEqual(record.state, RoundState.RED_PROPOSED)
        reference = record.artifacts["red_proposal"]
        self.assertEqual(artifacts.load("red_proposal", reference)["task_id"], round_id)
        self.assertEqual(record.attempt_log[-1].outcome, "succeeded")

    def test_component_task_mismatch_fails_the_active_round(self):
        manager, _artifacts, inputs, _outputs = manager_and_adapters()
        req = request()
        round_id = req["task_id"]
        inputs.open_round(req)
        proposal = load_json(CONTRACTS / "red_proposal/examples/valid_red_proposal.json")
        proposal["task_id"] = "another-round"

        inputs.begin_attempt(round_id)
        with self.assertRaises(ComponentFailure) as caught:
            inputs.accept_step_result(round_id, RoundState.RED_PROPOSED, {"red_proposal": proposal})

        self.assertEqual(caught.exception.category, "validation")
        self.assertEqual(caught.exception.round_record.state, RoundState.FAILED)


class OutputAdapterTests(unittest.TestCase):
    def test_red_input_comes_from_frozen_config_and_hides_executable_rule(self):
        manager, artifacts, inputs, outputs = manager_and_adapters()
        req = request()
        round_id = req["task_id"]
        inputs.open_round(req)

        message = outputs.build_red_input(round_id)

        self.assertEqual(message["task_id"], round_id)
        self.assertEqual(message["prompt_version"], req["versions"]["red_prompt"])
        self.assertNotIn("rule_text", message["detection"])

    def test_blue_input_accepts_an_explicit_version_matched_spl_representation(self):
        manager, artifacts, inputs, outputs = manager_and_adapters()
        req = request()
        round_id = req["task_id"]
        inputs.open_round(req)
        evidence_view = {
            "task_id": round_id,
            "detection_id": req["detection"]["detection_id"],
            "false_positives": [{"evidence_reference": {"evidence_id": "fp-1", "evidence_type": "reviewed_label"}, "observed_fields": {"User": "svc"}}],
            "must_detect": [{"evidence_reference": {"evidence_id": "atk-1", "evidence_type": "reviewed_label"}, "observed_fields": {"Image": "powershell.exe"}}],
        }

        blue_input = outputs.build_blue_input(
            round_id,
            evidence_view,
            {"allowed_operations": ["add_exclusion"], "allowed_fields": ["User"], "max_edits": 1},
            blue_detection={
                "detection_id": req["detection"]["detection_id"],
                "rule_version": req["detection"]["rule_version"],
                "rule_format": "spl",
                "rule_text": req["detection"]["rule_text"],
                "logic_summary": req["detection"]["logic_summary"],
            },
        )

        self.assertEqual(blue_input["detection"]["rule_format"], "spl")
        self.assertEqual(blue_input["detection"]["rule_text"], req["detection"]["rule_text"])


class CrossContractTests(unittest.TestCase):
    def test_known_good_shared_examples_join_against_the_frozen_round(self):
        config = RoundManager(InMemoryRoundStore()).create_round(request()).config
        proposal = load_json(CONTRACTS / "blue_proposal/examples/valid_blue_proposal.json")
        proposal["task_id"] = config.task_id

        candidate_rule = load_json(CONTRACTS / "candidate_rule/examples/valid_candidate_rule.json")
        candidate_rule.update(
            task_id=config.task_id,
            detection_id=config.detection["detection_id"],
            proposal_id=proposal["proposal_id"],
            base_rule_version=config.detection["rule_version"],
        )
        candidate = load_json(CONTRACTS / "candidate_rule/examples/valid_match_set.json")
        candidate.update(
            task_id=config.task_id,
            detection_id=config.detection["detection_id"],
            candidate_ref=candidate_rule["candidate_id"],
            rule_version=candidate_rule["candidate_rule_version"],
        )
        baseline = copy.deepcopy(candidate)
        baseline["match_set_id"] = "baseline-set-1"
        baseline["role"] = "baseline"
        baseline["rule_version"] = config.detection["rule_version"]
        baseline.pop("candidate_ref")
        baseline["matches"] = [{"event_id": "evt-0007"}]
        labels = load_json(CONTRACTS / "telemetry_evidence/examples/valid_reviewed_label_set.json")

        validate_judge_evidence(config, proposal, candidate_rule, baseline, candidate, labels)


class TemporarySchemaTests(unittest.TestCase):
    def test_interface_local_temporary_contract_files_are_valid_json(self):
        schema_dir = ROOT / "interfaces" / "contracts"
        for path in schema_dir.glob("*.schema.json"):
            with self.subTest(schema=path.name):
                schema = load_json(path)
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertTrue(schema["$id"].startswith("autosoc://orchestrator/interfaces/"))


class SharedJudgeInputContractTests(unittest.TestCase):
    def test_judge_input_uses_the_published_shared_contract(self):
        from orchestrator_interfaces.validation import ContractValidationError, InterfaceValidator

        req = request()
        task_id = req["task_id"]
        baseline = load_json(CONTRACTS / "candidate_rule/examples/valid_match_set.json")
        baseline.update(
            match_set_id="judge-baseline",
            task_id=task_id,
            role="baseline",
            detection_id=req["detection"]["detection_id"],
            rule_version=req["detection"]["rule_version"],
            dataset=req["dataset"],
        )
        baseline.pop("candidate_ref", None)
        candidate = load_json(CONTRACTS / "candidate_rule/examples/valid_match_set.json")
        candidate.update(
            match_set_id="judge-candidate",
            task_id=task_id,
            role="candidate",
            detection_id=req["detection"]["detection_id"],
            rule_version="candidate-v1",
            candidate_ref="candidate-1",
            dataset=req["dataset"],
        )
        labels = load_json(CONTRACTS / "telemetry_evidence/examples/valid_reviewed_label_set.json")
        payload = {
            "contract_version": "0.1.0",
            "judge_input_id": f"judge-input-{task_id}",
            "task_id": task_id,
            "detection_id": req["detection"]["detection_id"],
            "baseline_match_set": baseline,
            "candidate_match_set": candidate,
            "reviewed_label_set": labels,
            "criteria": req["criteria"]["thresholds"],
            "versions": req["versions"],
        }
        validator = InterfaceValidator(repo_root=ROOT.parent)

        accepted = validator.validate("judge_input", payload)
        self.assertEqual(accepted["judge_input_id"], f"judge-input-{task_id}")

        payload.pop("judge_input_id")
        with self.assertRaises(ContractValidationError):
            validator.validate("judge_input", payload)

