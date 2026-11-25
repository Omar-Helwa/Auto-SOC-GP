from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
UPLOADER_PATH = (
    REPO_ROOT
    / "05_platform_integrations"
    / "labelled_data"
    / "public_datasets"
    / "scripts"
    / "upload_to_splunk.py"
)
spec = importlib.util.spec_from_file_location("upload_to_splunk", UPLOADER_PATH)
assert spec is not None and spec.loader is not None
uploader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uploader)


class _Response:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.body = body
        self.status = status

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self.body


def test_post_requires_successful_hec_acknowledgement(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = []

    def successful_response(request, *, timeout: int, context: object) -> _Response:
        requests.append(request)
        return _Response(b'{"text":"Success","code":0}')

    monkeypatch.setattr(uploader.urllib.request, "urlopen", successful_response)

    uploader.post(
        "https://splunk.example:8088",
        "test-token",
        b'{"event":"test"}\n',
        None,
    )

    assert requests[0].get_header("Authorization") == "Splunk test-token"
    assert requests[0].full_url == "https://splunk.example:8088/services/collector/event"


@pytest.mark.parametrize(
    "body",
    [b'{"text":"Invalid token","code":1}', b"not-json"],
)
def test_post_rejects_failed_or_malformed_hec_acknowledgement(
    monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    monkeypatch.setattr(
        uploader.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(body),
    )

    with pytest.raises(RuntimeError, match="HEC"):
        uploader.post(
            "https://splunk.example:8088",
            "test-token",
            b'{"event":"test"}\n',
            None,
        )


def test_post_surfaces_transport_reason_without_echoing_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed_request(*_args: object, **_kwargs: object) -> None:
        raise OSError("TLS protocol mismatch for test-token")

    monkeypatch.setattr(uploader.urllib.request, "urlopen", failed_request)

    with pytest.raises(RuntimeError, match="TLS protocol mismatch") as caught:
        uploader.post(
            "https://splunk.example:8088",
            "test-token",
            b'{"event":"test"}\n',
            None,
        )
    assert "test-token" not in str(caught.value)


def test_plain_http_requires_explicit_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SPLUNK_HEC_ALLOW_INSECURE_HTTP", raising=False)
    with pytest.raises(ValueError, match="plain HTTP is disabled"):
        uploader._validate_hec_url("http://splunk.example:8088")

    monkeypatch.setenv("SPLUNK_HEC_ALLOW_INSECURE_HTTP", "1")
    uploader._validate_hec_url("http://splunk.example:8088")
    uploader._validate_hec_url("https://splunk.example:8088")
