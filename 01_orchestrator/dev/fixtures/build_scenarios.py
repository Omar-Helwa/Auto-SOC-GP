"""Regenerate the checked-in fixed requests and expected summaries."""

from __future__ import annotations

import json
from pathlib import Path


DEV_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = DEV_ROOT.parents[1]
SOURCE = REPO_ROOT / "00_shared_contracts" / "round_request" / "examples" / "valid_round_request.json"
REQUESTS = DEV_ROOT / "fixtures" / "round_requests"
EXPECTED = DEV_ROOT / "fixtures" / "expected"

SCENARIOS = {
    "pass": ("completed", "pass"),
    "reject": ("completed", "reject"),
    "inconclusive": ("inconclusive", "inconclusive"),
    "malformed_output": ("failed", "failed"),
    "retry_exhaustion": ("failed", "failed"),
    "timeout": ("failed", "failed"),
    "partial_persistence_failure": ("completed", "pass"),
}

ATTEMPTS = {
    "pass": {"red_proposed": ["succeeded"], "telemetry_collected": ["succeeded"], "evidence_verified": ["succeeded"], "blue_proposed": ["succeeded"], "candidate_executed": ["succeeded"], "judged": ["succeeded"]},
    "reject": {"red_proposed": ["succeeded"], "telemetry_collected": ["succeeded"], "evidence_verified": ["succeeded"], "blue_proposed": ["succeeded"], "candidate_executed": ["succeeded"], "judged": ["succeeded"]},
    "inconclusive": {"red_proposed": ["succeeded"], "telemetry_collected": ["succeeded"], "evidence_verified": ["succeeded"], "blue_proposed": ["succeeded"], "candidate_executed": ["succeeded"], "judged": ["succeeded"]},
    "malformed_output": {"red_proposed": ["failed"]},
    "retry_exhaustion": {"red_proposed": ["failed", "failed"]},
    "timeout": {"red_proposed": ["failed"]},
    "partial_persistence_failure": {"red_proposed": ["succeeded"], "telemetry_collected": ["succeeded"], "evidence_verified": ["failed", "succeeded"], "blue_proposed": ["succeeded"], "candidate_executed": ["succeeded"], "judged": ["succeeded"]},
}


def main() -> None:
    request = json.loads(SOURCE.read_text(encoding="utf-8"))
    REQUESTS.mkdir(parents=True, exist_ok=True)
    EXPECTED.mkdir(parents=True, exist_ok=True)
    for scenario, (state, outcome) in SCENARIOS.items():
        fixed = json.loads(json.dumps(request))
        fixed["task_id"] = f"dev-{scenario.replace('_', '-')}"
        if scenario == "retry_exhaustion":
            fixed["limits"]["max_attempts_per_step"] = 2
        if scenario == "timeout":
            fixed["limits"]["step_timeout_seconds"] = 1
        (REQUESTS / f"{scenario}.json").write_text(
            json.dumps(fixed, indent=2) + "\n", encoding="utf-8"
        )
        expected = {
            "scenario": scenario,
            "terminal_state": state,
            "outcome": outcome,
            "attempt_outcomes": ATTEMPTS[scenario],
            "required_storage": ["round_record", "audit_records"],
        }
        if scenario in {"malformed_output", "retry_exhaustion", "timeout"}:
            expected["error_category"] = {
                "malformed_output": "validation",
                "retry_exhaustion": "dependency",
                "timeout": "timeout",
            }[scenario]
        if state == "completed":
            expected["required_storage"].extend(["feedback_record", "referenced_contract_artifacts"])
        (EXPECTED / f"{scenario}.json").write_text(
            json.dumps(expected, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
