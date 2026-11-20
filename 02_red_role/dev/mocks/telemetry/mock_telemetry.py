"""Mock telemetry (Epic F3) — synthetic evidence references for tests.

Red cites evidence references only (never raw evidence). This provides a couple
of permitted-evidence-ref dicts a test can feed into a red_input when a task
needs prior evidence context.
"""

from __future__ import annotations

SAMPLE_EVIDENCE_REFS = [
    {
        "evidence_id": "ev-2026-11-10-encoded-ps-baseline",
        "evidence_type": "reviewed_label",
        "provenance_ref": "platform/evidence_store/ev-2026-11-10-encoded-ps-baseline",
    },
    {
        "evidence_id": "ev-2026-11-12-inventory-run",
        "evidence_type": "splunk_result",
        "provenance_ref": "platform/evidence_store/ev-2026-11-12-inventory-run",
    },
]


def sample_refs(n: int = 1) -> list[dict]:
    return [dict(r) for r in SAMPLE_EVIDENCE_REFS[:n]]
