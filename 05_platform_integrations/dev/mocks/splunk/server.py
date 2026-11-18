"""Local Splunk REST stub used by platform integration tests."""

from __future__ import annotations

import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from time import sleep
from typing import Any
from urllib.parse import parse_qs, urlsplit


EVENTS: list[dict[str, Any]] = [
    {
        "_time": "2026-01-02T03:04:05Z",
        "_cd": "0:123",
        "_raw": "failed login for alice",
        "host": "workstation-01",
        "source": "auth.log",
        "sourcetype": "linux_secure",
        "user": "alice",
        "action": "failure",
    },
    {
        "_time": "2026-01-02T03:05:05Z",
        "_raw": "successful login for bob",
        "host": "workstation-02",
        "user": "bob",
        "action": "success",
    },
]


class SplunkStubHandler(BaseHTTPRequestHandler):
    server_version = "SplunkStub/1.0"

    def do_POST(self) -> None:
        if urlsplit(self.path).path != "/servicesNS/nobody/search/search/jobs/export":
            self.send_error(404)
            return

        expected = "Basic " + base64.b64encode(b"test-user:test-password").decode("ascii")
        if self.headers.get("Authorization") != expected:
            self.send_error(401)
            return

        if self.server.response_mode == "unavailable":
            self.send_error(503, "Splunk unavailable")
            return
        if self.server.response_mode == "delay":
            sleep(self.server.delay_seconds)

        size = int(self.headers.get("Content-Length", "0"))
        params = parse_qs(self.rfile.read(size).decode("utf-8"))
        self.server.last_search = params  # type: ignore[attr-defined]
        body = "".join(
            json.dumps({"preview": False, "offset": index, "result": event}) + "\n"
            for index, event in enumerate(EVENTS)
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass

    def log_message(self, format: str, *args: object) -> None:
        return


class SplunkStubServer(ThreadingHTTPServer):
    last_search: dict[str, list[str]] | None = None
    response_mode = "success"
    delay_seconds = 0.2


def create_server() -> SplunkStubServer:
    return SplunkStubServer(("127.0.0.1", 0), SplunkStubHandler)
