"""Send prepared/<eval_set_id>/events/splunk_hec.jsonl to Splunk via HTTP Event Collector.

Before running, in Splunk create indexes `autosoc_attack` and `autosoc_benign`
and an HEC token allowed to write to both.

Env vars:
    SPLUNK_HEC_URL    e.g. https://localhost:8088
    SPLUNK_HEC_TOKEN  the HEC token (never commit it)
    SPLUNK_HEC_VERIFY_TLS  "0" to skip TLS verification for a local self-signed lab only
    SPLUNK_HEC_ALLOW_INSECURE_HTTP  "1" to explicitly permit plaintext HTTP in an isolated lab

Usage:
    python upload_to_splunk.py ../prepared/evalset-ps-v1/events/splunk_hec.jsonl
"""
from __future__ import annotations

import os
import ssl
import sys
import urllib.request
import json
from urllib.error import HTTPError, URLError
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv

BATCH = 500
REPO_ROOT = Path(__file__).resolve().parents[4]


def _validate_hec_url(url: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("SPLUNK_HEC_URL must be an origin-only http(s) URL without credentials")
    if (
        parsed.scheme == "http"
        and os.environ.get("SPLUNK_HEC_ALLOW_INSECURE_HTTP") != "1"
    ):
        raise ValueError(
            "plain HTTP is disabled; set SPLUNK_HEC_ALLOW_INSECURE_HTTP=1 "
            "for an explicitly approved isolated lab upload"
        )


def _safe_transport_detail(detail: object, url: str, token: str) -> str:
    text = str(detail)
    for secret in (token, url, url.rstrip("/")):
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


def post(url: str, token: str, body: bytes, ctx: ssl.SSLContext | None) -> None:
    req = urllib.request.Request(f"{url.rstrip('/')}/services/collector/event", data=body, method="POST",
                                 headers={"Authorization": f"Splunk {token}",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as response:
            if response.status != 200:
                raise RuntimeError(f"HEC returned HTTP {response.status}")
            try:
                acknowledgement = json.loads(response.read(4096).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("HEC returned an invalid acknowledgement") from exc
            if not isinstance(acknowledgement, dict) or type(acknowledgement.get("code")) is not int or acknowledgement["code"] != 0:
                raise RuntimeError("HEC rejected the batch")
    except HTTPError as exc:
        raise RuntimeError(f"HEC returned HTTP {exc.code}") from None
    except URLError as exc:
        detail = _safe_transport_detail(exc.reason, url, token)
        raise RuntimeError(f"HEC transport failed: {detail}") from None
    except TimeoutError:
        raise RuntimeError("HEC request timed out") from None
    except OSError as exc:
        detail = _safe_transport_detail(exc, url, token)
        raise RuntimeError(f"HEC transport failed: {detail}") from None


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    load_dotenv(REPO_ROOT / ".env", override=False)
    url, token = os.environ.get("SPLUNK_HEC_URL"), os.environ.get("SPLUNK_HEC_TOKEN")
    if not url or not token:
        print("Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN", file=sys.stderr)
        return 2
    try:
        _validate_hec_url(url)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    ctx = None
    if os.environ.get("SPLUNK_HEC_VERIFY_TLS") == "0":
        ctx = ssl._create_unverified_context()  # local lab only
    sent = 0
    batch: list[str] = []
    with Path(sys.argv[1]).open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            line = line.rstrip("\r\n")
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"Invalid JSON on input line {line_number}; stopping before its batch.", file=sys.stderr)
                return 1
            if not isinstance(event, dict) or "event" not in event:
                print(f"Invalid HEC event on input line {line_number}; stopping before its batch.", file=sys.stderr)
                return 1
            batch.append(line)
            if len(batch) == BATCH:
                try:
                    post(url, token, ("\n".join(batch) + "\n").encode("utf-8"), ctx)
                except RuntimeError as exc:
                    print(f"Upload stopped after {sent} acknowledged events: {exc}", file=sys.stderr)
                    return 1
                sent += len(batch)
                print(f"acknowledged {sent} events")
                batch.clear()
    if batch:
        try:
            post(url, token, ("\n".join(batch) + "\n").encode("utf-8"), ctx)
        except RuntimeError as exc:
            print(f"Upload stopped after {sent} acknowledged events: {exc}", file=sys.stderr)
            return 1
        sent += len(batch)
        print(f"acknowledged {sent} events")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
