from __future__ import annotations

import threading
import unittest

from dev.mocks.splunk.server import create_server
from splunk_execution import (
    ApprovedSearchRequest,
    SplunkApprovalError,
    SplunkClient,
    SplunkConfig,
    SplunkExecutionError,
)


class TestAuthorizer:
    def __init__(self, approved: bool = True) -> None:
        self.approved = approved
        self.requests: list[ApprovedSearchRequest] = []

    def is_approved(self, request: ApprovedSearchRequest) -> bool:
        self.requests.append(request)
        return self.approved


class SplunkExecutionTests(unittest.TestCase):
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

    def make_client(
        self,
        *,
        max_events: int = 10,
        password: str = "test-password",
        timeout_seconds: float = 1.0,
        approved: bool = True,
        base_url: str | None = None,
    ) -> SplunkClient:
        return SplunkClient(
            SplunkConfig(
                base_url=base_url or self.base_url,
                username="test-user",
                password=password,
                max_events=max_events,
                timeout_seconds=timeout_seconds,
                allow_insecure_http=True,
            ),
            TestAuthorizer(approved),
        )

    @staticmethod
    def operation() -> ApprovedSearchRequest:
        return ApprovedSearchRequest(
            task_id="task-42",
            task_version="3",
            operation_id="search-17",
            approval_id="approval-9",
            spl="search index=auth action=failure",
            earliest_time="-1h",
            latest_time="now",
        )

    def test_approved_search_records_provenance_and_normalizes_events(self) -> None:
        result = self.make_client().execute(self.operation())

        self.assertEqual(result.execution.status, "succeeded")
        self.assertEqual(result.execution.task_id, "task-42")
        self.assertEqual(result.execution.task_version, "3")
        self.assertEqual(result.execution.operation_id, "search-17")
        self.assertEqual(result.execution.approval_id, "approval-9")
        self.assertEqual(result.execution.event_count, 2)
        self.assertFalse(result.execution.truncated)
        self.assertEqual(len(result.execution.execution_id), 36)
        self.assertTrue(result.execution.started_at.endswith("Z"))
        self.assertTrue(result.execution.completed_at.endswith("Z"))
        self.assertEqual(result.search_result.events[0].event_id, "0:123")
        self.assertEqual(result.search_result.events[0].timestamp, "2026-01-02T03:04:05Z")
        self.assertEqual(result.search_result.events[0].fields["user"], "alice")
        self.assertEqual(result.search_result.events[0].raw, "failed login for alice")
        self.assertEqual(result.as_dict()["execution"]["approval_id"], "approval-9")
        self.assertEqual(self.server.last_search["search"], ["search index=auth action=failure"])
        self.assertEqual(self.server.last_search["earliest_time"], ["-1h"])
        self.assertEqual(self.server.last_search["latest_time"], ["now"])
        self.assertEqual(self.server.last_search["output_mode"], ["json"])
        self.assertEqual(self.server.last_search["max_count"], ["11"])
        self.assertEqual(
            self.server.last_search["output_time_format"], ["%Y-%m-%dT%H:%M:%S.%3N%:z"]
        )

    def test_unapproved_operation_is_rejected_before_splunk_access(self) -> None:
        with self.assertRaisesRegex(SplunkApprovalError, "not approved"):
            self.make_client(approved=False).execute(self.operation())

        self.assertIsNone(self.server.last_search)

    def test_invalid_operation_metadata_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "task_version"):
            ApprovedSearchRequest(
                task_id="task-42",
                task_version="",
                operation_id="search-17",
                approval_id="approval-9",
                spl="search index=auth",
            )

    def test_results_are_bounded_and_marked_truncated(self) -> None:
        result = self.make_client(max_events=1).execute(self.operation())

        self.assertEqual(len(result.search_result.events), 1)
        self.assertTrue(result.search_result.truncated)
        self.assertTrue(result.execution.truncated)
        self.assertEqual(self.server.last_search["max_count"], ["2"])

    def test_http_rejection_is_reported_in_failed_execution_record(self) -> None:
        with self.assertRaises(SplunkExecutionError) as caught:
            self.make_client(password="wrong").execute(self.operation())

        self.assertIn("HTTP 401", str(caught.exception))
        self.assertEqual(caught.exception.execution.status, "failed")
        self.assertEqual(caught.exception.execution.approval_id, "approval-9")
        self.assertIn("HTTP 401", caught.exception.execution.failure_reason)
        failure_record = caught.exception.as_dict()["execution"]
        self.assertEqual(failure_record["event_count"], 0)
        self.assertFalse(failure_record["truncated"])
        self.assertEqual(failure_record["failure_reason"], "Splunk returned HTTP 401")

    def test_unavailable_splunk_service_is_recorded(self) -> None:
        self.server.response_mode = "unavailable"

        with self.assertRaises(SplunkExecutionError) as caught:
            self.make_client().execute(self.operation())

        self.assertIn("HTTP 503", str(caught.exception))
        self.assertEqual(caught.exception.execution.status, "failed")

    def test_timeout_is_recorded(self) -> None:
        self.server.response_mode = "delay"

        with self.assertRaises(SplunkExecutionError) as caught:
            self.make_client(timeout_seconds=0.02).execute(self.operation())

        self.assertIn("timed out", str(caught.exception))
        self.assertEqual(caught.exception.execution.status, "failed")

    def test_unreachable_service_is_reported(self) -> None:
        offline_server = create_server()
        port = offline_server.server_port
        offline_server.server_close()

        with self.assertRaises(SplunkExecutionError) as caught:
            self.make_client(base_url=f"http://127.0.0.1:{port}").execute(
                self.operation()
            )

        self.assertRegex(
            str(caught.exception),
            "Could not connect to Splunk|Splunk request timed out",
        )
        self.assertEqual(caught.exception.execution.status, "failed")

    def test_http_requires_explicit_local_development_opt_in(self) -> None:
        with self.assertRaisesRegex(ValueError, "allow_insecure_http"):
            SplunkConfig(
                base_url=self.base_url,
                username="test-user",
                password="test-password",
            )


if __name__ == "__main__":
    unittest.main()
