from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from splunk_execution import (
    ApprovedSearchRequest,
    ManualCLIApprovalAuthorizer,
    SplunkClient,
)
from splunk_execution.config import (
    build_splunk_client_from_env,
    load_splunk_runtime_config,
)


class SplunkRuntimeConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = {
            "AUTOSOC_SPLUNK_URL": "https://localhost:8089",
            "AUTOSOC_SPLUNK_USERNAME": "test-user",
            "AUTOSOC_SPLUNK_PASSWORD": "test-password",
            "AUTOSOC_SPLUNK_APP": "search",
            "AUTOSOC_SPLUNK_INDEX": "lab_eval",
            "AUTOSOC_SPLUNK_SOURCETYPE": "XmlWinEventLog:Sysmon",
        }

    def load_config(self):
        with patch.dict(os.environ, self.environment, clear=True):
            with patch("splunk_execution.config.load_dotenv"):
                return load_splunk_runtime_config()

    def test_loads_credentials_and_literal_search_scope(self) -> None:
        runtime = self.load_config()

        self.assertEqual(runtime.connection.base_url, "https://localhost:8089")
        self.assertEqual(runtime.index, "lab_eval")
        self.assertEqual(runtime.sourcetype, "XmlWinEventLog:Sysmon")
        self.assertEqual(
            runtime.scoped_search,
            'search index=lab_eval sourcetype="XmlWinEventLog:Sysmon"',
        )
        self.assertTrue(runtime.connection.verify_tls)

    def test_requires_credentials_and_scope_without_echoing_secret(self) -> None:
        self.environment.pop("AUTOSOC_SPLUNK_PASSWORD")
        with self.assertRaisesRegex(
            ValueError, "AUTOSOC_SPLUNK_PASSWORD"
        ) as caught:
            self.load_config()
        self.assertNotIn("test-password", str(caught.exception))

    def test_rejects_web_port_and_wildcard_index(self) -> None:
        self.environment["AUTOSOC_SPLUNK_URL"] = "https://localhost:8000"
        with self.assertRaisesRegex(ValueError, "management API port"):
            self.load_config()

        self.environment["AUTOSOC_SPLUNK_URL"] = "https://localhost:8089"
        self.environment["AUTOSOC_SPLUNK_INDEX"] = "*"
        with self.assertRaisesRegex(ValueError, "literal index"):
            self.load_config()

    def test_rejects_invalid_numeric_controls(self) -> None:
        self.environment["AUTOSOC_SPLUNK_TIMEOUT_SECONDS"] = "NaN"
        with self.assertRaisesRegex(ValueError, "greater than zero"):
            self.load_config()

        self.environment["AUTOSOC_SPLUNK_TIMEOUT_SECONDS"] = "30"
        self.environment["AUTOSOC_SPLUNK_MAX_EVENTS"] = "1.5"
        with self.assertRaisesRegex(ValueError, "must be an integer"):
            self.load_config()

    def test_builds_client_from_loaded_environment(self) -> None:
        with patch.dict(os.environ, self.environment, clear=True):
            with patch("splunk_execution.config.load_dotenv"):
                client = build_splunk_client_from_env(
                    ManualCLIApprovalAuthorizer("lab_eval")
                )
        self.assertIsInstance(client, SplunkClient)


class ManualCLIApprovalTests(unittest.TestCase):
    @staticmethod
    def request(spl: str) -> ApprovedSearchRequest:
        return ApprovedSearchRequest(
            task_id="task-42",
            task_version="1",
            operation_id="search-1",
            approval_id="approval-9",
            spl=spl,
            earliest_time="-15m",
        )

    def test_accepts_exact_confirmation_for_literal_index_search(self) -> None:
        prompts: list[str] = []
        authorizer = ManualCLIApprovalAuthorizer(
            "lab_eval",
            confirm=lambda prompt: (
                prompts.append(prompt) or "APPROVE approval-9"
            ),
        )

        approved = authorizer.is_approved(
            self.request('search index=lab_eval sourcetype="XmlWinEventLog"')
        )

        self.assertTrue(approved)
        self.assertIn("APPROVE approval-9", prompts[0])
        self.assertIn('sourcetype="XmlWinEventLog"', prompts[0])

    def test_rejects_wrong_confirmation_and_out_of_scope_or_pipeline_searches(self) -> None:
        def wrong_confirmation(prompt: str) -> str:
            self.assertIn("Approval reference", prompt)
            return "APPROVE wrong-id"

        authorizer = ManualCLIApprovalAuthorizer(
            "lab_eval", confirm=wrong_confirmation
        )
        self.assertFalse(
            authorizer.is_approved(self.request("search index=lab_eval"))
        )

        authorizer = ManualCLIApprovalAuthorizer(
            "lab_eval",
            confirm=lambda prompt: self.fail(
                f"unsafe search must not prompt: {prompt}"
            ),
        )
        for spl in (
            "search index=production",
            "search index=lab_eval OR index=production",
            "search index=lab_eval | delete",
        ):
            with self.subTest(spl=spl):
                self.assertFalse(authorizer.is_approved(self.request(spl)))

    def test_non_interactive_authorizer_refuses_without_prompting(self) -> None:
        authorizer = ManualCLIApprovalAuthorizer("lab_eval")
        with patch("splunk_execution.approval.sys.stdin") as stdin:
            stdin.isatty.return_value = False
            self.assertFalse(
                authorizer.is_approved(self.request("search index=lab_eval"))
            )

    def test_pipeline_requires_opt_in_and_only_allows_read_only_commands(self) -> None:
        request = self.request(
            "search index=lab_eval EventID=8 | stats count | convert ctime(count)"
        )
        self.assertFalse(ManualCLIApprovalAuthorizer("lab_eval").is_approved(request))

        approved = ManualCLIApprovalAuthorizer(
            "lab_eval",
            allow_read_only_pipeline=True,
            confirm=lambda _prompt: "APPROVE approval-9",
        )
        self.assertTrue(approved.is_approved(request))
        for command in ("delete", "outputlookup", "eval"):
            with self.subTest(command=command):
                unsafe = self.request(f"search index=lab_eval | {command} value")
                self.assertFalse(approved.is_approved(unsafe))

    def test_end_of_input_refuses_approval(self) -> None:
        authorizer = ManualCLIApprovalAuthorizer("lab_eval")
        with patch("splunk_execution.approval.sys.stdin") as stdin:
            stdin.isatty.return_value = True
            with patch("builtins.input", side_effect=EOFError):
                self.assertFalse(
                    authorizer.is_approved(self.request("search index=lab_eval"))
                )


if __name__ == "__main__":
    unittest.main()
