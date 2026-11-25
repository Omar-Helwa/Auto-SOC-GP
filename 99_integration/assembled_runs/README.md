# Assembled runs

`run_with_real_red_and_blue.py` runs one round with the real components:

| Step (owned by the Orchestrator) | Component | Implementation |
|---|---|---|
| Red proposal | Red | `adapters/red_service.py` (mock gateway unless a hosted provider is selected) |
| Telemetry collection, evidence verification | Platform | `adapters/platform_service.py` -> `05_platform_integrations` |
| Blue context, Blue proposal | Platform, Blue | `platform_service.py` builds the context; `adapters/blue_service.py` runs Blue |
| Candidate execution | Platform | `platform_service.py` -> `ProposalExecutionService.run_blue_proposal` |
| Acceptance decision | Judge | `adapters/judge_service.py` (deterministic Judge) |

The Orchestrator (`01_orchestrator`, through `shared_services.RoundController`)
is the only code that decides step order, retries, and terminal state. The
Platform adapter never decides acceptance; the Judge is the only source of
`PASS`, `REJECT`, or `INCONCLUSIVE`. The runner no longer contains fixture
Platform evidence.

## What the Platform adapter does

Each round makes three Splunk searches. All three are read-only, start with
`search index=<AUTOSOC_SPLUNK_INDEX>`, and are restricted to the frozen
evaluation set by the indexed HEC field `autosoc_eval_set`:

1. **Telemetry** (`collect_telemetry`): `search index=<index>
   autosoc_eval_set::<evaluation_set_id>`. The results are stored in the
   content-hashed `EvidenceStore`; the step returns `evidence_store:<id>`.
   Red's workflow steps are scenario text only. Nothing is executed on a
   host, and the search does not depend on Red's text.
2. **Baseline** (`verify_evidence`): the frozen detection, scoped as above.
   The step returns `telemetry_evidence`, the `reviewed_label_set` read
   unchanged from `prepared/<evaluation_set_id>/labels/`, and a
   `baseline_match_set`.
3. **Candidate** (`execute_candidate`): Blue's edits compiled by
   `validation.rule_compiler.compile_candidate_rule` against the same scoped
   base rule. The approved SPL, the executed SPL, and
   `candidate_rule.compiled_rule.text` are byte-identical.

`build_blue_context` joins telemetry, labels, and baseline matches by
`event_id`. False positives are reviewed benign events the baseline matched.
Must-detect cases are reviewed attack events. Blue sees only the fields it
may edit (`allowed_fields`, `attacker_controllable_fields`) plus fields the
rule references. Other telemetry fields are not passed to Blue.

### Approval binding

`ManualCLIApprovalAuthorizer(require_binding=True)` prompts for every
search. The prompt shows the task, round-request version, operation,
proposal, dataset ID, version, evaluation-set ID, checksum, index scope,
time range, and exact SPL. The approval reference is
`apv-<sha256 of all of these>`
(`splunk_execution.approval.bound_approval_id`). Type
`APPROVE <reference>` to run the search. If any bound field changes, the
authorizer refuses the request without prompting. Before using a result,
the adapter checks that the evidence record carries the expected approval
and operation IDs. A retry after a timeout or outage needs a new approval.

### Evidence checks (fail closed)

The adapter raises a classified `ServiceAdapterError`, which the
Orchestrator records as an `error_response`, when any of these is true:

- The round dataset lacks `dataset_id`, `dataset_version`,
  `evaluation_set_id`, or `evaluation_set_checksum`.
- The label set is malformed, has `coverage.complete=false`, contains any
  unreviewed or disputed label, has a reviewed label without a reviewer,
  differs from the round dataset, or its event IDs do not hash to the
  checksum. This check runs before any search is requested.
- `AUTOSOC_SPLUNK_MAX_EVENTS` is smaller than the frozen set.
- A Splunk result is empty or truncated, or it lacks the indexed `event_id`.
  A `_cd` or content-hash fallback ID is not a label identity, so the
  adapter rejects it.
- Telemetry event IDs differ from the label IDs, or they do not hash to the
  checksum.
- A baseline or candidate match is outside the label set, a match set is not
  `completed`, or a match set's dataset differs from the frozen dataset.
- Stored evidence fails its integrity hash, or the evidence belongs to
  another task, proposal, detection, or approval.
- A Blue edit uses an operation the Platform did not allow. Only
  `add_exclusion` is supported, because the scoped base rule has no named
  selections.

Splunk failures are classified as follows:

| Failure | Category | Retryable |
|---|---|---|
| Timeout | `timeout` | yes |
| Connection failure or HTTP 5xx | `dependency` | yes |
| TLS verification failure | `dependency` | no; the message names `AUTOSOC_SPLUNK_CA_CERT` |
| Other HTTP errors | `dependency` | no |
| Splunk search errors and malformed results | `validation` | no |

### Event-level rule projection

Splunk `stats` output has no per-event identity, so it cannot be joined to
labels. `validation.rule_compiler.event_level_search` executes the rule's
search head plus one `field=*` filter per `stats ... by` field. An event
contributes to a `stats by` row only when every by-field is present.
`convert` and a final `search *` are dropped because they do not filter.
Rules with a tail that filters aggregated values are rejected. For the
imported LSASS rule `67d4dbef-...` the baseline SPL is:

```
search index=autosoc_lab autosoc_eval_set::evalset-demo-lsass-v1 ((source=WinEventLog:Microsoft-Windows-Sysmon/Operational OR source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational) EventID=8 TargetImage="*\\lsass.exe") dest=* signature_id=* signature=* SourceProcessGuid=* SourceProcessId=* SourceImage=* TargetProcessGuid=* TargetProcessId=* TargetImage=* StartModule=* StartFunction=* vendor_product=*
```

The match set measures which events the rule alerts on. It does not reproduce
the rule's aggregated output.

## Mock versus live boundary

| | Tests (`99_integration/contract_tests`) | Runner |
|---|---|---|
| Splunk | Local REST stub over HTTP (`05_platform_integrations/dev/mocks/splunk/server.py`), real `SplunkClient` | Splunk management API from `.env`, HTTPS with verification required |
| Approval | Real authorizer, scripted operator | Real authorizer, interactive operator |
| Labels | Reviewed test fixture in a temporary directory | `prepared/<evaluation_set_id>` as built and reviewed by a human |
| Red / Blue models | Red mock gateway, Blue deterministic | `--provider` / `AUTOSOC_MODEL_PROVIDER` (default: mock Red, deterministic Blue) |
| MongoDB | `mongomock` | Persistent MongoDB (`fallback_to_mock=False`), pinged first |
| Judge | Real | Real |

The tests make no Splunk, Groq, xAI, or Atlas calls.

## Setup

1. Build or obtain a frozen evaluation set under
   `05_platform_integrations/labelled_data/public_datasets/prepared/<id>/`
   (see that folder's README). A human reviewer must review the labels and
   rebuild the set with `--reviewer`. The label set must have
   `coverage.complete=true` and an `evaluation_set_checksum`. It must also
   include at least one benign event that the baseline matches, or Blue has
   nothing to fix.
2. Upload `events/splunk_hec.jsonl` to the index named by
   `AUTOSOC_SPLUNK_INDEX`. Public attack datasets keep their original
   timestamps (the LSASS events are from 2020). Splunk's default retention
   (`frozenTimePeriodInSecs = 188697600`, about 6 years) deletes older
   events, so raise it for the lab index (for example `473040000`) before
   uploading. The HEC payloads name `autosoc_attack` and
   `autosoc_benign`. Re-target them, or index the set so that both classes
   are in the single approved index. Each event must keep its indexed
   `event_id` and `autosoc_eval_set` fields. For Sysmon XML, Splunk must
   extract fields such as `EventID` and `TargetImage`. The CIM fields the
   LSASS rule groups by (`dest`, `signature`, `signature_id`,
   `vendor_product`) must also exist, or the baseline matches nothing. Use
   the official Splunk Add-on for Sysmon, or, when Splunkbase is unavailable,
   the search-time stand-in
   `05_platform_integrations/splunk_apps/autosoc_sysmon_fields`. Install it
   with `install_autosoc_sysmon_fields.ps1`, run elevated. Its `dest`,
   `signature`, `signature_id` and `vendor_product` are derived from
   `Computer` and `EventID`. They approximate the official add-on's values;
   the baseline only tests that they are present. Do not install both.
3. Configure `.env` (never commit it):

   ```dotenv
   AUTOSOC_SPLUNK_URL=https://localhost:8089
   AUTOSOC_SPLUNK_USERNAME=...
   AUTOSOC_SPLUNK_PASSWORD=...
   AUTOSOC_SPLUNK_INDEX=autosoc_lab
   AUTOSOC_SPLUNK_CA_CERT='C:\path\to\splunk-ca.pem' # CA that signed the Splunk server cert; single quotes keep backslashes literal
   AUTOSOC_SPLUNK_MAX_EVENTS=1000                    # must be >= the frozen set size
   ```

   The runner refuses `AUTOSOC_SPLUNK_VERIFY_TLS=false` and plain HTTP. The
   certificate must name the host in `AUTOSOC_SPLUNK_URL`. Splunk's default
   self-signed certificate does not name `localhost`, so issue a server
   certificate with `subjectAltName=DNS:localhost` and point
   `AUTOSOC_SPLUNK_CA_CERT` at its CA. `AUTOSOC_SPLUNK_SOURCETYPE` is not
   applied to round searches, because a frozen set can span sourcetypes.
4. Make MongoDB reachable through `AUTOSOC_MONGO_URI` / `MONGODB_URI`. The
   database defaults to `autosoc_assembled`; override it with `AUTOSOC_DB`.
   The runner pings MongoDB before it opens a round.

## Run

```powershell
# Offline: validate labels, detection, rule scope, and Splunk/TLS settings. No network calls.
python 99_integration/assembled_runs/run_with_real_red_and_blue.py --preflight-only

# Live: prompts to approve each of the three searches.
python 99_integration/assembled_runs/run_with_real_red_and_blue.py --evaluation-set <id>
```

Options:

- `--detection-id`: required when the set has more than one detection.
- `--edit-constraints FILE`: Blue's `edit_constraints` JSON. A default
  exists only for the LSASS demo rule.
- `--earliest-time`, `--latest-time`: bound into every approval. The
  default is all time (`0` to `now`), because public datasets keep their
  original timestamps.
- `--evidence-dir`: defaults to `99_integration/reports/platform_evidence/`,
  which is git-ignored.
- `--provider none|mock|xai|groq`

With a hosted provider (`xai`, `groq`), Blue would send the projected
fields of Splunk-measured events to that provider. The runner refuses
this when any label has `source` other than `public_dataset`. For
public-dataset-only sets, it requires
`--allow-public-telemetry-to-hosted-model`. Credentials are read from the
environment and are never printed.

Run the tests from the repository root:

```powershell
python -m pytest 99_integration/contract_tests -q
```

## Current limitations

- The local prepared sets (`evalset-demo-lsass-v1`, `evalset-ps-v1`,
  `evalset-multi-v1`) are unreviewed, with `coverage.complete=false`.
  Preflight rejects them, and no Judge evaluation can be claimed from them.
- `evalset-demo-lsass-v1` contains no benign events that the LSASS rule
  matches. Its benign events are SOCBED process-creation and PowerShell
  events. Even after review, Blue would have no false positive to remove,
  and the round would stop at Blue context construction.
- Searches are limited to one index. Telemetry over the frozen set must fit
  within `AUTOSOC_SPLUNK_MAX_EVENTS`; large sets such as
  `evalset-multi-v1` (45,338 events) are rejected rather than truncated.
- Approval is an interactive local operator prompt. A deployment should
  replace it with a trusted approval service that implements the same
  binding.
