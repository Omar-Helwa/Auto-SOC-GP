# Mock round sandbox

Run from `01_orchestrator`:

```powershell
python -m dev.sandbox.run_mock_round --scenario pass
python -m dev.sandbox.run_mock_round --scenario reject
python -m dev.sandbox.run_mock_round --scenario inconclusive
python -m dev.sandbox.run_mock_round --scenario malformed_output
python -m dev.sandbox.run_mock_round --scenario retry_exhaustion
python -m dev.sandbox.run_mock_round --scenario timeout
python -m dev.sandbox.run_mock_round --scenario partial_persistence_failure
```

The same contract-shaped mock services can use Mongo persistence:

```powershell
python -m dev.sandbox.run_mock_round --scenario pass --storage mongo --db-name autosoc_mock_sandbox
```

Mongo uses `AUTOSOC_MONGO_URI` and `AUTOSOC_DB` by default; `--mongo-uri` and
`--db-name` override them. The runner does not call real models, Judge,
Platform, or Splunk services. Mongo output is written to the selected database;
memory mode is discarded when the process exits. Each fixed fixture reuses its
task ID, so use a fresh Mongo database for a repeat run of the same scenario or
the existing round will be rejected as a duplicate.

The fixture builder regenerates the fixed requests and expected summaries:

```powershell
python dev/fixtures/build_scenarios.py
```

Run just the scenario checks with:

```powershell
python -m unittest dev.tests.test_dev_scenarios -v
```

Run all Orchestrator tests, including Mongo persistence checks, with:

```powershell
python -m unittest discover -s dev/tests -v
```

Mongo integration tests are skipped if no MongoDB server is reachable. They
use mock component services and do not verify compatibility with the real
Blue or deterministic Judge input interfaces. The real Judge handoff is
currently blocked by the missing shared input contract and the different
shapes expected by the Orchestrator and Judge.

`dev/temp_outputs/` is for disposable outputs only. The round store, contract
artifact store, and audit store remain the authoritative records.
