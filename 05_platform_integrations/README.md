# Platform integrations

## Shared model gateway

The shared gateway is owned by Platform and injected into Red and Blue by the
adapters under `99_integration/`. Blue's standalone deterministic and mock
providers remain available for offline component tests.

Install the optional hosted-model dependencies:

```powershell
python -m pip install -r 05_platform_integrations/requirements.txt
```

Select either xAI's Grok API or Groq-hosted models. Keep their credentials
separate; `grok` is an alias for the xAI provider, not for Groq.

For xAI:

```dotenv
XAI_API_KEY=your-xai-api-key
AUTOSOC_MODEL_PROVIDER=xai
AUTOSOC_MODEL_ID=grok-4.7
```

For Groq:

```dotenv
GROQ_API_KEY=your-groq-api-key
AUTOSOC_MODEL_PROVIDER=groq
GROQ_MODEL_ID=openai/gpt-oss-20b
```

Both providers share the timeout and retry controls:

```dotenv
AUTOSOC_MODEL_TIMEOUT_SECONDS=60
AUTOSOC_MODEL_MAX_RETRIES=2
```

`XAI_API_KEY` and `GROQ_API_KEY` may be loaded from the repository-root `.env`;
process environment values take precedence. `GROQ_KEY` is also accepted for
Groq, along with the older `XAI_KEY` alias. Neither Groq variable is used for
xAI authentication. Both adapters use their provider's Responses API,
request JSON output, and send `store=false`. SDK retries and timeouts are
configured centrally. Responses include the provider-reported model id, UTC
generation timestamp, token counts, provider response id, and a SHA-256
reference for the raw text. The raw text is returned to the calling component
and is not written to disk by the gateway.

The assembled runner accepts `--provider xai`, `--provider groq`, or the
corresponding `AUTOSOC_MODEL_PROVIDER` value. No live provider call is made by
the test suite.

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

### Local connection check

For the local MVP, `splunk_execution.config` reads `AUTOSOC_SPLUNK_URL`,
`AUTOSOC_SPLUNK_USERNAME`, `AUTOSOC_SPLUNK_PASSWORD`, `AUTOSOC_SPLUNK_APP`,
`AUTOSOC_SPLUNK_INDEX`, and optional `AUTOSOC_SPLUNK_SOURCETYPE` from the
repository-root `.env` (process environment values take precedence). Use the
Splunk management API URL, normally `https://localhost:8089`; port 8000 is the
Splunk Web UI, not the search API. TLS verification remains enabled by default.
Optional controls are `AUTOSOC_SPLUNK_VERIFY_TLS`,
`AUTOSOC_SPLUNK_CA_CERT`, `AUTOSOC_SPLUNK_ALLOW_INSECURE_HTTP`,
`AUTOSOC_SPLUNK_TIMEOUT_SECONDS`, and `AUTOSOC_SPLUNK_MAX_EVENTS`.

Run this from `05_platform_integrations` in an interactive terminal:

```powershell
python -m splunk_execution.connection_check
```

The command constructs a search restricted to the configured literal index
and optional sourcetype, defaults to the last 15 minutes, caps results at 10,
and prompts for explicit approval of the exact SPL and time range. It reports
only the event count and execution metadata, not telemetry contents. Use
`--earliest-time` or `--latest-time` to adjust the diagnostic range. This
operator prompt is a local MVP boundary; deployments should inject their
trusted platform approval service in place of `ManualCLIApprovalAuthorizer`.

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
