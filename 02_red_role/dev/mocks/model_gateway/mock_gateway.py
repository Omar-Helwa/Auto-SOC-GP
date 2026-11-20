"""Mock model gateway (Epic F2) — deterministic responses, no hosted model.

Implements the ModelGateway protocol. Modes:
  normal      -> a valid scenario JSON (admin_automation, 2 benign steps)
  malformed   -> non-JSON text
  refusal     -> a refusal sentence
  timeout     -> raises ModelTimeout
  unavailable -> raises ModelUnavailable

`custom_text` overrides the returned text (e.g. to force an out-of-scope family
for bounds testing).
"""

from __future__ import annotations

import json

# interfaces is on sys.path (component root) when the component runs/tests.
from interfaces.model_gateway import (
    ModelGateway,
    ModelResponse,
    ModelTimeout,
    ModelUnavailable,
)

_NORMAL_PROPOSAL = {
    "scenario": {
        "family": "admin_automation",
        "title": "Scheduled base64 PowerShell inventory script",
        "description": (
            "A sanctioned IT automation runs a base64-encoded PowerShell command "
            "from a scheduled task to collect an asset inventory."
        ),
        "workflow_steps": [
            {
                "action": "scheduled_task",
                "target": "\\Microsoft\\Windows\\AssetInventory\\DailyScan",
                "parameters": {"run_as": "svc_inventory", "schedule": "daily-02:00"},
                "benign_context": "Pre-existing sanctioned inventory task registered by IT.",
            },
            {
                "action": "script_execution",
                "target": "powershell.exe -EncodedCommand <base64>",
                "parameters": {"decoded_intent": "Get-CimInstance Win32_Product"},
                "benign_context": "Encoded only to survive scheduler quoting; lists software.",
            },
        ],
        "expected_signal": "The -EncodedCommand argument may match the encoded-PowerShell pattern.",
    },
    "benign_justification": (
        "Asset inventory collection is a standard, documented IT operation; the "
        "encoding is a quoting workaround, not obfuscation."
    ),
    "rationale": "Legitimate encoded PowerShell is a frequent false-positive source.",
    "evidence_references": [],
}

# A scenario whose family/action are often NOT allowed by a given round,
# used to exercise the bounds checker.
_OUT_OF_SCOPE_PROPOSAL = {
    "scenario": {
        "family": "security_tooling",
        "title": "Vulnerability scan sweep",
        "description": "An authorized scanner probes hosts across the subnet.",
        "workflow_steps": [
            {
                "action": "network_connection",
                "target": "nessus-scanner -> 10.0.0.0/24",
                "benign_context": "Scheduled authorized vulnerability scan.",
            }
        ],
        "expected_signal": "Burst of connections may match a scanning detection.",
    },
    "benign_justification": "Routine authorized vulnerability scanning.",
    "rationale": "Scanners commonly trigger network detections.",
    "evidence_references": [],
}


class MockModelGateway(ModelGateway):
    def __init__(self, mode: str = "normal", custom_text: str | None = None):
        self.mode = mode
        self.custom_text = custom_text
        self.calls: list[dict] = []

    def generate(self, system: str, task: str, params: dict | None = None) -> ModelResponse:
        self.calls.append({"system": system, "task": task, "params": params or {}})

        if self.custom_text is not None:
            return ModelResponse(text=self.custom_text, model_id="mock-model@fixed")

        if self.mode == "timeout":
            raise ModelTimeout("mock gateway timeout")
        if self.mode == "unavailable":
            raise ModelUnavailable("mock gateway unavailable")
        if self.mode == "malformed":
            return ModelResponse(text="not json at all { broken", model_id="mock-model@malformed")
        if self.mode == "refusal":
            return ModelResponse(
                text="I'm sorry, I can't help with that.", model_id="mock-model@refusal"
            )
        if self.mode == "out_of_scope":
            return ModelResponse(text=json.dumps(_OUT_OF_SCOPE_PROPOSAL), model_id="mock-model@oos")
        # normal
        return ModelResponse(text=json.dumps(_NORMAL_PROPOSAL), model_id="mock-model@normal")
