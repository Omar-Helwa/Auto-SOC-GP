"""Run a manually approved, bounded read-only search to verify Splunk connectivity."""

from __future__ import annotations

import argparse
from dataclasses import replace
from uuid import uuid4

from .approval import ManualCLIApprovalAuthorizer
from .client import (
    ApprovedSearchRequest,
    SplunkClient,
    SplunkApprovalError,
    SplunkExecutionError,
)
from .config import load_splunk_runtime_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--earliest-time", default="-15m")
    parser.add_argument("--latest-time", default="now")
    args = parser.parse_args(argv)

    runtime = load_splunk_runtime_config()
    runtime = replace(
        runtime,
        connection=replace(
            runtime.connection, max_events=min(runtime.connection.max_events, 10)
        ),
    )
    client = SplunkClient(
        runtime.connection,
        ManualCLIApprovalAuthorizer(runtime.index),
    )
    operation = ApprovedSearchRequest(
        task_id="splunk-connection-check",
        task_version="1",
        operation_id=str(uuid4()),
        approval_id=str(uuid4()),
        spl=runtime.scoped_search,
        earliest_time=args.earliest_time,
        latest_time=args.latest_time,
    )
    try:
        result = client.execute(operation)
    except SplunkApprovalError:
        print("Splunk connection check was not approved.")
        return 1
    except SplunkExecutionError as exc:
        print(f"Splunk connection check failed: {exc.execution.failure_reason}")
        return 1

    print(
        "Splunk search succeeded: "
        f"{result.execution.event_count} event(s); "
        f"truncated={result.execution.truncated}; "
        f"execution_id={result.execution.execution_id}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
