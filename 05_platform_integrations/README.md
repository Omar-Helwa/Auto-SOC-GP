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

For deployments, supply credentials through a secret manager or environment
configuration; do not commit them to source control. The authorizer should
resolve and verify approvals independently rather than trusting caller-
controlled request properties.
