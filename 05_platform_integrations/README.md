# Platform integrations

## Splunk approved execution

`SplunkClient` accepts an `ApprovedSearchRequest` and a trusted
`OperationAuthorizer`. The authorizer must verify the approval reference against
the platform's trusted validation/permission boundary; request fields by
themselves are not proof of approval. Rejected or malformed requests never
reach Splunk. This adapter executes searches only: it does not select workflow
order, author proposals, or decide whether a candidate passes.

The client uses Basic authentication over HTTPS, verifies server certificates
by default, and never includes credentials in the request URL. For a private
CA, set `ca_cert` to its PEM file. Plain HTTP is rejected unless
`allow_insecure_http=True` is explicitly configured for an isolated local
mock. Disabling TLS verification is intended only for local development.

```python
from splunk_execution import (
    ApprovedSearchRequest,
    SplunkClient,
    SplunkConfig,
)

client = SplunkClient(
    SplunkConfig(
        base_url="https://splunk.example:8089",
        username="service-account",
        password="load-this-from-a-secret-store",
        app="search",
        max_events=500,
    ),
    authorizer=trusted_platform_approval_service,
)
operation = ApprovedSearchRequest(
    task_id="task-42",
    task_version="3",
    operation_id="search-17",
    approval_id="approval-9",
    spl="search index=auth action=failure",
    earliest_time="-1h",
    latest_time="now",
)
result = client.execute(operation)
execution_record = result.execution.as_dict()
evidence = [event.as_dict() for event in result.search_result.events]
```

Each evidence record contains an event ID, event timestamp, a `fields` mapping,
and any available host/source/sourcetype/raw values. When Splunk does not return
an event ID, a stable SHA-256 ID is derived from the returned event fields.
Successful results include an execution record with task/version/operation/
approval references, timestamps, status, event count, and truncation status.
`SplunkExecutionError` contains the failure execution record, including the
precise failure reason; approval rejection raises `SplunkApprovalError` before
an execution starts.

The request, evidence, and search-result shapes are documented in
`interfaces/inputs/splunk_search.schema.json`,
`interfaces/outputs/telemetry_evidence.schema.json`, and
`interfaces/outputs/splunk_search_result.schema.json`; failed execution records
match `interfaces/outputs/splunk_execution_error.schema.json`. The local Splunk
mock supports success, authentication rejection, service unavailability, and
delayed responses for timeout testing. Run the mock-backed tests from this
directory:

```powershell
python -m unittest discover -s dev -p "test_*.py"
```

## Proposal execution (data-flow steps 3 and 5)

`ProposalExecutionService` is the platform boundary consumed by the orchestrator;
it does not sequence the round or make a pass/reject decision. Red proposals are
validated against the shared schema and paired with a separate
`ApprovedSearchRequest`. The platform runs only that approved Splunk search,
returns the measured events in the shared
`00_shared_contracts/telemetry_evidence/telemetry_evidence.schema.json`
contract, and persists the immutable record under `evidence_store/`. Red
workflow steps remain scenario descriptions: the service never launches them
as endpoint commands.

Blue proposals are validated and compiled from a trusted `BaseRule`. Its
read-only `spl_template` may use `{{selection_name}}` placeholders backed by
trusted selection fragments. The compiler supports the contract's
`add_exclusion` and `narrow_selection` operations and rejects unknown selection
targets. Before execution, the separately approved search must exactly equal
the compiled candidate SPL. The service returns a schema-valid `candidate_rule`
and candidate `match_set`, with a reference to the persisted Splunk evidence.
Truncated runs are marked `partial`; failures and rejections propagate explicit
errors and never return success-shaped evidence.

Example construction:

```python
from evidence_store.store import EvidenceStore
from proposal_execution import ProposalExecutionService

platform = ProposalExecutionService(
    splunk_client,
    EvidenceStore("path/to/platform-evidence"),
)
red_result = platform.run_red_proposal(
    red_proposal,
    approved_red_search,  # approval binds task_id and proposal_id
)
blue_result = platform.run_blue_proposal(
    blue_proposal,
    base_rule,
    candidate_rule_version="3.2.1-candidate-1",
    approved_search=approved_candidate_search,
    dataset={
        "dataset_id": "lab-sysmon",
        "dataset_version": "2026.11.1",
        "evaluation_set_id": "evalset-01",
    },
)
```

The blue approved-search request must carry the same `proposal_id` and frozen
`dataset` reference as the method arguments. The trusted authorizer must verify
these fields, the approval reference, and the exact search before allowing
Splunk access.

For deployments, supply credentials through a secret manager or environment
configuration; do not commit them to source control. The authorizer should
resolve and verify approvals independently rather than trusting caller-
controlled request properties.
