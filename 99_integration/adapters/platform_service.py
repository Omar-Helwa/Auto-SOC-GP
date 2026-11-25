"""Adapt the real Platform integrations to the Orchestrator ``PlatformService`` protocol.

The Orchestrator decides when each operation runs and the deterministic Judge
decides acceptance. This adapter only:

* runs approved, read-only, index-scoped Splunk searches through
  ``ProposalExecutionService`` (``05_platform_integrations``);
* persists each measured result in the content-verified ``EvidenceStore``;
* checks that telemetry, reviewed labels, baseline matches, and candidate
  matches use one event identity (``event_id``) and the frozen dataset. In the
  live composition that identity is recomputed from each returned raw event
  (``validation.events``), as the dataset builder defines it; and
* projects verified evidence into the Blue input context.

Red workflow steps are never executed. The telemetry search retrieves the
frozen evaluation set that is already indexed in Splunk; it is not derived
from Red's scenario text.

Every search is bound to its approval: the ``approval_id`` is derived from
the task, round-request version, operation, proposal, full dataset reference,
index scope, time range, and exact SPL (see
``splunk_execution.approval.bound_approval_id``). The authorizer refuses a
request whose fields no longer match its id, and the adapter re-checks the
binding recorded in each evidence record before using it.

Failures raise ``ServiceAdapterError`` with an ``error_response`` category.
No step substitutes fixture or success-shaped evidence, and labels are read
as-is: unreviewed or incomplete label sets are rejected, never promoted.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import json
import os
import re
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterator, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
PLATFORM_ROOT = REPO_ROOT / "05_platform_integrations"
ORCHESTRATOR_ROOT = REPO_ROOT / "01_orchestrator"
ADAPTER_ROOT = Path(__file__).resolve().parent
DEFAULT_PREPARED_ROOT = (
    PLATFORM_ROOT / "labelled_data" / "public_datasets" / "prepared"
)
DEFAULT_EVIDENCE_DIR = REPO_ROOT / "99_integration" / "reports" / "platform_evidence"

for _path in (PLATFORM_ROOT, ORCHESTRATOR_ROOT, ADAPTER_ROOT):
    if str(_path) not in sys.path:
        sys.path.append(str(_path))

from evidence_store.store import EvidenceStore, EvidenceStoreError  # noqa: E402
from proposal_execution import ProposalExecutionService  # noqa: E402
from shared_services.controller.services import ServiceAdapterError  # noqa: E402
from splunk_execution import (  # noqa: E402
    ApprovedSearchRequest,
    ManualCLIApprovalAuthorizer,
    SplunkApprovalError,
    SplunkClient,
    SplunkExecutionError,
    load_splunk_runtime_config,
)
from splunk_execution.approval import (  # noqa: E402
    bound_approval_id,
    is_scoped_read_only_search,
)
from validation.events import normalize_frozen_set_event  # noqa: E402
from validation.labels import (  # noqa: E402
    LabelSetNotReady,
    evaluation_set_checksum,
    load_prepared_label_set,
    require_frozen_dataset,
    require_judge_ready_label_set,
)
from validation.proposals import ContractValidationError, require_valid_contract  # noqa: E402
from validation.rule_compiler import (  # noqa: E402
    BaseRule,
    compile_candidate_rule,
    event_level_search,
    render_base_rule,
)

_workflow_models = importlib.import_module("workflow.models")
BlueInputContext = _workflow_models.BlueInputContext
WorkflowStepOutput = _workflow_models.WorkflowStepOutput

EVIDENCE_REF_PREFIX = "evidence_store:"
_EVAL_SET_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_OBSERVED_FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_QUOTED = re.compile(r'"(?:\\.|[^"\\])*"')
_FIELD_TERM = re.compile(r"(?:^|[\s(])([A-Za-z_][A-Za-z0-9_.]*)\s*!?=(?!=)")
_MAX_OBSERVED_FIELDS = 30
_SUPPORTED_OPERATIONS = frozenset({"add_exclusion"})


@dataclass(frozen=True)
class PlatformSearchSettings:
    """Fixed search scope shared by the authorizer and every Platform search."""

    index: str
    earliest_time: str = "0"
    latest_time: str = "now"
    max_events: int | None = None
    # Indexed HEC field written by the dataset builders for each event.
    eval_set_field: str = "autosoc_eval_set"

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", self.index):
            raise ValueError("index must be one literal index name")
        if not _EVAL_SET_FIELD.fullmatch(self.eval_set_field):
            raise ValueError("eval_set_field must be a plain field name")
        for name in ("earliest_time", "latest_time"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or not value.isprintable():
                raise ValueError(f"{name} must be a printable, non-empty string")
        if self.max_events is not None and self.max_events <= 0:
            raise ValueError("max_events must be positive")


class SplunkPlatformService:
    """Workflow Platform operations backed by approval-gated Splunk searches."""

    def __init__(
        self,
        executor: ProposalExecutionService,
        evidence_store: EvidenceStore,
        *,
        settings: PlatformSearchSettings,
        edit_constraints: Mapping[str, Any],
        prepared_root: str | Path = DEFAULT_PREPARED_ROOT,
    ) -> None:
        self._executor = executor
        self._store = evidence_store
        self._settings = settings
        self._prepared_root = Path(prepared_root)
        self._edit_constraints = _validated_edit_constraints(edit_constraints)

    # ------------------------------------------------------------------ preflight

    def preflight(self, round_request: Mapping[str, Any]) -> dict[str, Any]:
        """Offline readiness check: frozen dataset, reviewed labels, and rule scope.

        Makes no Splunk call. The workflow operations repeat these checks.
        """
        with _platform_errors("preflight"):
            dataset = require_frozen_dataset(round_request.get("dataset"))
            labels = self._ready_labels(dataset)
            base_rule = self._base_rule(round_request)
            return {
                "label_set_id": labels["label_set_id"],
                "total_events": labels["coverage"]["total_events"],
                "label_sources": sorted({label["source"] for label in labels["labels"]}),
                "telemetry_spl": self._telemetry_spl(dataset),
                "baseline_spl": render_base_rule(base_rule),
            }

    # ---------------------------------------------------------- workflow protocol

    def collect_telemetry(
        self, round_request: Mapping[str, Any], red_proposal: Mapping[str, Any]
    ) -> Any:
        with _platform_errors("telemetry collection"):
            dataset = require_frozen_dataset(round_request.get("dataset"))
            # Reject unusable ground truth before asking anyone to approve a search.
            labels = self._ready_labels(dataset)
            self._require_red_proposal(round_request, red_proposal)
            request = self._approved_request(
                round_request, "telemetry", red_proposal["proposal_id"],
                self._telemetry_spl(dataset),
            )
            execution = self._executor.run_red_proposal(red_proposal, request)
            evidence = execution.telemetry_evidence
            self._verify_telemetry(evidence, request, labels, round_request, red_proposal)
            return WorkflowStepOutput(
                raw_output_ref=f"{EVIDENCE_REF_PREFIX}{evidence['evidence_id']}",
                raw_output=_execution_summary(evidence, request),
                detail=(
                    f"approved Splunk telemetry search returned {len(evidence['events'])} "
                    f"events for evaluation set {dataset['evaluation_set_id']}"
                ),
            )

    def verify_evidence(
        self,
        round_request: Mapping[str, Any],
        red_proposal: Mapping[str, Any],
        telemetry_ref: str,
    ) -> Any:
        with _platform_errors("evidence verification"):
            dataset = require_frozen_dataset(round_request.get("dataset"))
            labels = self._ready_labels(dataset)
            self._require_red_proposal(round_request, red_proposal)
            evidence = self._store.get(_evidence_id_from_ref(telemetry_ref))
            require_valid_contract(evidence, "telemetry_evidence")
            telemetry_request = self._approved_request(
                round_request, "telemetry", red_proposal["proposal_id"],
                self._telemetry_spl(dataset),
            )
            self._verify_telemetry(
                evidence, telemetry_request, labels, round_request, red_proposal
            )

            base_rule = self._base_rule(round_request)
            baseline_request = self._approved_request(
                round_request, "baseline", red_proposal["proposal_id"],
                render_base_rule(base_rule),
            )
            baseline = dict(
                self._executor.run_baseline_rule(
                    base_rule,
                    proposal_id=red_proposal["proposal_id"],
                    approved_search=baseline_request,
                    dataset=dataset,
                ).match_set
            )
            self._verify_match_set(
                baseline, baseline_request, labels, dataset,
                role="baseline", rule_version=base_rule.rule_version,
            )
            return WorkflowStepOutput(
                messages={
                    "telemetry_evidence": evidence,
                    "reviewed_label_set": labels,
                    "baseline_match_set": baseline,
                },
                raw_output={
                    "telemetry": _execution_summary(evidence, telemetry_request),
                    "baseline": {
                        "match_set_id": baseline["match_set_id"],
                        "execution_id": baseline["execution"]["execution_id"],
                        "approval_id": baseline_request.approval_id,
                        "match_count": len(baseline["matches"]),
                        "spl_sha256": _sha256(baseline_request.spl),
                    },
                    "label_set_id": labels["label_set_id"],
                },
                detail=(
                    f"verified {len(evidence['events'])} telemetry events against "
                    f"{labels['label_set_id']}; baseline matched {len(baseline['matches'])}"
                ),
            )

    def build_blue_context(
        self, round_request: Mapping[str, Any], artifacts: Mapping[str, Mapping[str, Any]]
    ) -> Any:
        with _platform_errors("Blue context construction"):
            missing = [
                name for name in ("telemetry_evidence", "reviewed_label_set", "baseline_match_set")
                if name not in artifacts
            ]
            if missing:
                raise ServiceAdapterError(
                    f"Blue context requires verified Platform artifacts: missing {missing}",
                    category="missing_information",
                )
            dataset = require_frozen_dataset(round_request.get("dataset"))
            labels = dict(artifacts["reviewed_label_set"])
            require_judge_ready_label_set(labels, dataset)
            if labels != self._ready_labels(dataset):
                raise ServiceAdapterError(
                    "stored reviewed_label_set differs from the frozen label source",
                    category="validation",
                )
            detection = round_request["detection"]
            from blue_service import platform_evidence_cases

            false_positives, must_detect = platform_evidence_cases(
                dict(round_request),
                dict(artifacts["telemetry_evidence"]),
                labels,
                dict(artifacts["baseline_match_set"]),
                task_id=round_request["task_id"],
                detection_id=detection["detection_id"],
                observed_fields=self._observed_fields(round_request),
            )
            return BlueInputContext(
                evidence_view={
                    "task_id": round_request["task_id"],
                    "detection_id": detection["detection_id"],
                    "false_positives": false_positives,
                    "must_detect": must_detect,
                },
                edit_constraints=dict(self._edit_constraints),
                blue_detection={
                    "detection_id": detection["detection_id"],
                    "rule_version": detection["rule_version"],
                    "rule_format": "spl",
                    "rule_text": detection["rule_text"],
                    "logic_summary": detection["logic_summary"],
                },
                prior_blue_edits=None,
            )

    def execute_candidate(
        self,
        round_request: Mapping[str, Any],
        blue_proposal: Mapping[str, Any],
        baseline_match_set: Mapping[str, Any] | None,
    ) -> Any:
        with _platform_errors("candidate execution"):
            if baseline_match_set is None:
                raise ServiceAdapterError(
                    "candidate execution requires the verified baseline match set",
                    category="missing_information",
                )
            dataset = require_frozen_dataset(round_request.get("dataset"))
            labels = self._ready_labels(dataset)
            require_valid_contract(blue_proposal, "blue_proposal")
            unsupported = sorted(
                {edit["operation"] for edit in blue_proposal["edits"]}
                - set(self._edit_constraints["allowed_operations"])
            )
            if unsupported:
                raise ServiceAdapterError(
                    f"blue_proposal uses operation(s) the Platform did not allow: {unsupported}",
                    category="validation",
                )
            base_rule = self._base_rule(round_request)
            baseline = dict(baseline_match_set)
            reference = baseline.get("evidence_reference")
            if not isinstance(reference, Mapping) or not reference.get("evidence_id"):
                raise ServiceAdapterError(
                    "baseline match set has no evidence reference", category="missing_information"
                )
            # The baseline was approved for the Red proposal that opened the
            # round; rebuild that binding from its stored evidence and re-check it.
            baseline_evidence = self._store.get(reference["evidence_id"])
            baseline_request = self._approved_request(
                round_request, "baseline", baseline_evidence["proposal_id"],
                render_base_rule(base_rule),
            )
            self._verify_match_set(
                baseline, baseline_request, labels, dataset,
                role="baseline", rule_version=base_rule.rule_version,
            )

            preview = compile_candidate_rule(
                blue_proposal, base_rule, candidate_rule_version="preview"
            )
            spl = preview["compiled_rule"]["text"]
            candidate_version = f"{base_rule.rule_version}-cand-{_sha256(spl)[:12]}"
            request = self._approved_request(
                round_request, "candidate", blue_proposal["proposal_id"], spl
            )
            execution = self._executor.run_blue_proposal(
                blue_proposal,
                base_rule,
                candidate_rule_version=candidate_version,
                approved_search=request,
                dataset=dataset,
            )
            candidate_rule = dict(execution.candidate_rule)
            match_set = dict(execution.match_set)
            compiled = candidate_rule["compiled_rule"]
            if compiled["text"] != request.spl or compiled["sha256"] != _sha256(request.spl):
                raise ServiceAdapterError(
                    "compiled candidate rule differs from the approved and executed SPL",
                    category="validation",
                )
            if match_set.get("candidate_ref") != candidate_rule["candidate_id"]:
                raise ServiceAdapterError(
                    "candidate match set does not reference the compiled candidate rule",
                    category="validation",
                )
            self._verify_match_set(
                match_set, request, labels, dataset,
                role="candidate", rule_version=candidate_version,
            )
            return WorkflowStepOutput(
                messages={
                    "candidate_rule": candidate_rule,
                    "candidate_match_set": match_set,
                },
                raw_output={
                    "candidate_id": candidate_rule["candidate_id"],
                    "match_set_id": match_set["match_set_id"],
                    "execution_id": match_set["execution"]["execution_id"],
                    "approval_id": request.approval_id,
                    "match_count": len(match_set["matches"]),
                    "spl_sha256": compiled["sha256"],
                },
                detail=(
                    f"approved candidate search matched {len(match_set['matches'])} events; "
                    "acceptance is decided by the Judge"
                ),
            )

    # ------------------------------------------------------------------ helpers

    def _ready_labels(self, dataset: Mapping[str, Any]) -> dict[str, Any]:
        labels = load_prepared_label_set(self._prepared_root, dataset["evaluation_set_id"])
        require_judge_ready_label_set(labels, dataset)
        total = labels["coverage"]["total_events"]
        if self._settings.max_events is not None and total > self._settings.max_events:
            raise ServiceAdapterError(
                f"the frozen set has {total} events but Splunk results are capped at "
                f"{self._settings.max_events}; the telemetry search would be truncated. "
                "Raise AUTOSOC_SPLUNK_MAX_EVENTS or use a smaller frozen set.",
                category="missing_information",
            )
        return labels

    def _require_red_proposal(
        self, round_request: Mapping[str, Any], red_proposal: Mapping[str, Any]
    ) -> None:
        require_valid_contract(red_proposal, "red_proposal")
        if red_proposal["task_id"] != round_request["task_id"]:
            raise ServiceAdapterError("red_proposal belongs to a different task", category="validation")
        if red_proposal["detection_under_test"]["detection_id"] != round_request["detection"]["detection_id"]:
            raise ServiceAdapterError("red_proposal targets a different detection", category="validation")

    def _telemetry_spl(self, dataset: Mapping[str, Any]) -> str:
        return (
            f"search index={self._settings.index} "
            f"{self._settings.eval_set_field}::{dataset['evaluation_set_id']}"
        )

    def _base_rule(self, round_request: Mapping[str, Any]) -> BaseRule:
        detection = round_request["detection"]
        if detection.get("rule_language") != "splunk_spl":
            raise ServiceAdapterError(
                "the Platform executes only splunk_spl detections", category="validation"
            )
        dataset = round_request["dataset"]
        template = (
            f"search index={self._settings.index} "
            f"{self._settings.eval_set_field}::{dataset['evaluation_set_id']} "
            f"{event_level_search(detection['rule_text'])}"
        )
        if not is_scoped_read_only_search(template, self._settings.index):
            raise ServiceAdapterError(
                f"detection SPL references an index or construct outside the approved "
                f"scope index={self._settings.index}",
                category="validation",
            )
        return BaseRule(
            task_id=round_request["task_id"],
            detection_id=detection["detection_id"],
            rule_version=detection["rule_version"],
            spl_template=template,
            selections={},
        )

    def _approved_request(
        self, round_request: Mapping[str, Any], purpose: str, proposal_id: str, spl: str
    ) -> ApprovedSearchRequest:
        task_id = round_request["task_id"]
        pending = ApprovedSearchRequest(
            task_id=task_id,
            task_version=_round_request_version(round_request),
            operation_id=f"{task_id}:{purpose}",
            approval_id="pending",
            spl=spl.strip(),
            earliest_time=self._settings.earliest_time,
            latest_time=self._settings.latest_time,
            proposal_id=proposal_id,
            dataset=require_frozen_dataset(round_request["dataset"]),
        )
        return replace(pending, approval_id=bound_approval_id(pending, self._settings.index))

    def _verify_telemetry(
        self,
        evidence: Mapping[str, Any],
        request: ApprovedSearchRequest,
        labels: Mapping[str, Any],
        round_request: Mapping[str, Any],
        red_proposal: Mapping[str, Any],
    ) -> None:
        evidence_id = evidence["evidence_id"]
        if (
            evidence["task_id"] != round_request["task_id"]
            or evidence["proposal_id"] != red_proposal["proposal_id"]
            or evidence["detection_id"] != round_request["detection"]["detection_id"]
        ):
            raise ServiceAdapterError(
                f"telemetry evidence {evidence_id} belongs to a different task, proposal, or detection",
                category="validation",
            )
        _require_execution_binding(evidence, request)
        execution = evidence["execution"]
        events = evidence["events"]
        if execution["truncated"]:
            raise ServiceAdapterError(
                f"telemetry search was truncated after {execution['event_count']} events "
                f"(evidence {evidence_id}); the frozen set has "
                f"{labels['coverage']['total_events']} events",
                category="missing_information",
                details={"evidence_id": evidence_id},
            )
        if not events:
            raise ServiceAdapterError(
                f"telemetry search returned no events for evaluation set "
                f"{request.dataset['evaluation_set_id']} in index {self._settings.index} "
                f"({request.earliest_time} to {request.latest_time}); the frozen set is not "
                "available in Splunk",
                category="missing_information",
                details={"evidence_id": evidence_id},
            )
        if execution["event_count"] != len(events):
            raise ServiceAdapterError(
                f"telemetry evidence {evidence_id} event_count disagrees with its events",
                category="validation",
            )
        ids = [event["event_id"] for event in events]
        if len(ids) != len(set(ids)):
            raise ServiceAdapterError(
                f"telemetry evidence {evidence_id} contains duplicate event_id values",
                category="validation",
            )
        label_ids = {label["event_id"] for label in labels["labels"]}
        unexpected = sorted(set(ids) - label_ids)
        missing = sorted(label_ids - set(ids))
        if unexpected:
            raise ServiceAdapterError(
                f"telemetry contains {len(unexpected)} events outside the frozen label set "
                f"(for example {unexpected[:3]}); every event needs the stable event_id "
                "indexed with the evaluation set",
                category="validation",
                details={"evidence_id": evidence_id, "unexpected_count": len(unexpected)},
            )
        if missing:
            raise ServiceAdapterError(
                f"telemetry is missing {len(missing)} of {len(label_ids)} labelled events "
                f"(for example {missing[:3]})",
                category="missing_information",
                details={"evidence_id": evidence_id, "missing_count": len(missing)},
            )
        if evaluation_set_checksum(ids) != request.dataset["evaluation_set_checksum"]:
            raise ServiceAdapterError(
                "telemetry event IDs do not hash to the frozen evaluation_set_checksum",
                category="validation",
            )

    def _verify_match_set(
        self,
        match_set: Mapping[str, Any],
        request: ApprovedSearchRequest,
        labels: Mapping[str, Any],
        dataset: Mapping[str, Any],
        *,
        role: str,
        rule_version: str,
    ) -> None:
        require_valid_contract(match_set, "match_set")
        if match_set["role"] != role or match_set["rule_version"] != rule_version:
            raise ServiceAdapterError(
                f"{role} match set role or rule_version does not match the frozen round",
                category="validation",
            )
        if dict(match_set["dataset"]) != dict(dataset):
            raise ServiceAdapterError(
                f"{role} match set dataset differs from the frozen round dataset",
                category="validation",
            )
        if match_set["execution"]["status"] != "completed":
            raise ServiceAdapterError(
                f"{role} search did not complete (status {match_set['execution']['status']}); "
                "truncated or partial match sets are not evidence",
                category="missing_information",
            )
        ids = [match["event_id"] for match in match_set["matches"]]
        if len(ids) != len(set(ids)):
            raise ServiceAdapterError(
                f"{role} match set contains duplicate event_id values", category="validation"
            )
        label_ids = {label["event_id"] for label in labels["labels"]}
        unknown = sorted(set(ids) - label_ids)
        if unknown:
            raise ServiceAdapterError(
                f"{role} matched {len(unknown)} events outside the frozen label set "
                f"(for example {unknown[:3]})",
                category="validation",
            )
        reference = match_set.get("evidence_reference")
        if not reference:
            raise ServiceAdapterError(
                f"{role} match set has no evidence reference", category="missing_information"
            )
        evidence = self._store.get(reference["evidence_id"])
        if evidence["execution"]["execution_id"] != match_set["execution"]["execution_id"]:
            raise ServiceAdapterError(
                f"{role} match set does not reference its own execution evidence",
                category="validation",
            )
        _require_execution_binding(evidence, request)
        if match_set["execution"].get("search_ref") != request.operation_id:
            raise ServiceAdapterError(
                f"{role} match set search_ref differs from the approved operation",
                category="validation",
            )

    def _observed_fields(self, round_request: Mapping[str, Any]) -> list[str]:
        """Fields Blue may see: those it may edit plus those the rule references."""
        constraints = self._edit_constraints
        projected = event_level_search(round_request["detection"]["rule_text"])
        rule_fields = [
            name
            for name in _FIELD_TERM.findall(_QUOTED.sub('""', projected))
            if name.lower() != "index" and name != self._settings.eval_set_field
        ]
        names: list[str] = []
        for name in (
            *constraints["allowed_fields"],
            *constraints.get("attacker_controllable_fields", ()),
            *rule_fields,
        ):
            if _OBSERVED_FIELD.fullmatch(name) and name not in names:
                names.append(name)
        if len(names) > _MAX_OBSERVED_FIELDS:
            raise ServiceAdapterError(
                f"Blue may observe at most {_MAX_OBSERVED_FIELDS} fields; the edit constraints "
                f"and rule reference {len(names)}",
                category="validation",
            )
        return names


# ------------------------------------------------------------------ composition


def build_splunk_platform_service(
    *,
    edit_constraints: Mapping[str, Any],
    prepared_root: str | Path = DEFAULT_PREPARED_ROOT,
    evidence_dir: str | Path = DEFAULT_EVIDENCE_DIR,
    earliest_time: str = "0",
    latest_time: str = "now",
    env_file: str | Path | None = None,
) -> SplunkPlatformService:
    """Build the live adapter from the repository ``.env`` with an interactive approver.

    Requires HTTPS with certificate verification. A private or self-signed
    Splunk certificate is supported through ``AUTOSOC_SPLUNK_CA_CERT``; a
    verification bypass is refused here.
    """
    runtime = load_splunk_runtime_config(env_file)
    connection = runtime.connection
    if not connection.base_url.lower().startswith("https://") or connection.allow_insecure_http:
        raise ValueError("the assembled Platform requires an HTTPS Splunk management URL")
    if not connection.verify_tls:
        raise ValueError(
            "AUTOSOC_SPLUNK_VERIFY_TLS must stay enabled for the assembled Platform; "
            "set AUTOSOC_SPLUNK_CA_CERT to the Splunk server's CA (PEM) instead"
        )
    if connection.ca_cert and not os.path.isfile(connection.ca_cert):
        raise ValueError("AUTOSOC_SPLUNK_CA_CERT does not name a readable file")
    authorizer = ManualCLIApprovalAuthorizer(runtime.index, require_binding=True)
    store = EvidenceStore(evidence_dir)
    return SplunkPlatformService(
        ProposalExecutionService(
            SplunkClient(connection, authorizer),
            store,
            # Splunk's export does not return the indexed event_id or the
            # Sysmon fields; derive both from the returned raw text.
            event_normalizer=normalize_frozen_set_event,
        ),
        store,
        settings=PlatformSearchSettings(
            index=runtime.index,
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_events=connection.max_events,
        ),
        edit_constraints=edit_constraints,
        prepared_root=prepared_root,
    )


# ------------------------------------------------------------------ module helpers


@contextlib.contextmanager
def _platform_errors(operation: str) -> Iterator[None]:
    """Translate Platform failures into classified ``ServiceAdapterError``s."""
    try:
        yield
    except ServiceAdapterError:
        raise
    except SplunkApprovalError as exc:
        raise ServiceAdapterError(
            f"{operation}: Splunk search was not approved ({exc})",
            category="validation",
            details={"reason": "approval_rejected"},
        ) from exc
    except SplunkExecutionError as exc:
        category, retryable, hint = _classify_splunk_failure(exc.execution.failure_reason or str(exc))
        raise ServiceAdapterError(
            f"{operation}: Splunk search failed: {exc.execution.failure_reason}{hint}",
            category=category,
            retryable=retryable,
            details={"execution": exc.execution.as_dict()},
        ) from exc
    except LabelSetNotReady as exc:
        raise ServiceAdapterError(
            f"{operation}: {exc}", category="missing_information"
        ) from exc
    except EvidenceStoreError as exc:
        raise ServiceAdapterError(f"{operation}: {exc}", category="validation") from exc
    except ContractValidationError as exc:
        raise ServiceAdapterError(f"{operation}: {exc}", category="validation") from exc
    except ValueError as exc:
        raise ServiceAdapterError(f"{operation}: {exc}", category="validation") from exc


def _classify_splunk_failure(reason: str) -> tuple[str, bool, str]:
    if "timed out" in reason:
        return "timeout", True, ""
    if "CERTIFICATE_VERIFY_FAILED" in reason or "SSL" in reason:
        return "dependency", False, (
            " (TLS verification failed: configure AUTOSOC_SPLUNK_CA_CERT with the server's "
            "CA and make sure the certificate names the host in AUTOSOC_SPLUNK_URL)"
        )
    if reason.startswith(("Could not connect", "Splunk returned HTTP 5", "Splunk transport failed")):
        return "dependency", True, ""
    if reason.startswith("Splunk returned HTTP"):
        return "dependency", False, ""
    return "validation", False, ""


def _require_execution_binding(evidence: Mapping[str, Any], request: ApprovedSearchRequest) -> None:
    execution = evidence["execution"]
    if execution.get("status") != "succeeded":
        raise ServiceAdapterError(
            f"evidence {evidence['evidence_id']} is not a successful execution",
            category="validation",
        )
    if execution.get("approval_id") != request.approval_id or execution.get("operation_id") != request.operation_id:
        raise ServiceAdapterError(
            f"evidence {evidence['evidence_id']} was not produced by the approved "
            f"{request.operation_id} search",
            category="validation",
        )


def _evidence_id_from_ref(reference: Any) -> str:
    if not isinstance(reference, str) or not reference.startswith(EVIDENCE_REF_PREFIX):
        raise ServiceAdapterError(
            f"telemetry reference {reference!r} is not a Platform evidence_store reference",
            category="validation",
        )
    return reference[len(EVIDENCE_REF_PREFIX):]


def _execution_summary(evidence: Mapping[str, Any], request: ApprovedSearchRequest) -> dict[str, Any]:
    execution = evidence["execution"]
    return {
        "evidence_id": evidence["evidence_id"],
        "execution_id": execution["execution_id"],
        "operation_id": execution["operation_id"],
        "approval_id": execution["approval_id"],
        "event_count": execution["event_count"],
        "truncated": execution["truncated"],
        "spl_sha256": _sha256(request.spl),
        "earliest_time": request.earliest_time,
        "latest_time": request.latest_time,
    }


def _round_request_version(round_request: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        round_request, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")
    return "rr-" + hashlib.sha256(canonical).hexdigest()[:16]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _validated_edit_constraints(constraints: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(constraints, Mapping):
        raise ValueError("edit_constraints must be an object")
    value = json.loads(json.dumps(dict(constraints)))
    operations = value.get("allowed_operations")
    if not isinstance(operations, list) or not operations:
        raise ValueError("edit_constraints.allowed_operations must be a non-empty list")
    unsupported = sorted(set(operations) - _SUPPORTED_OPERATIONS)
    if unsupported:
        raise ValueError(
            f"edit operation(s) {unsupported} cannot be compiled: the Platform base rule "
            "for an SPL detection has no named selections"
        )
    fields = value.get("allowed_fields")
    if not isinstance(fields, list) or not fields or not all(
        isinstance(name, str) and _OBSERVED_FIELD.fullmatch(name) for name in fields
    ):
        raise ValueError("edit_constraints.allowed_fields must list plain field names")
    return value
