"""Run the Red component in isolation against a fixture (Epic G6).

Uses the mock model gateway, prints the result, and writes it to
dev/temp_outputs/. No real model or other services required.

    cd 02_red_role
    python dev/sandbox/run.py                      # normal round
    python dev/sandbox/run.py --mode timeout        # force a timeout error
    python dev/sandbox/run.py --fixture missing_info_task.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(COMPONENT_ROOT / "dev" / "mocks" / "model_gateway"))

from interfaces.red_role import RedRole          # noqa: E402
from mock_gateway import MockModelGateway          # noqa: E402

FIXTURES = COMPONENT_ROOT / "dev" / "fixtures"
TEMP_OUT = COMPONENT_ROOT / "dev" / "temp_outputs"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", default="valid_task.json")
    ap.add_argument("--mode", default="normal",
                    choices=["normal", "malformed", "refusal", "timeout", "unavailable", "out_of_scope"])
    args = ap.parse_args()

    raw = json.loads((FIXTURES / args.fixture).read_text(encoding="utf-8"))
    task = {k: v for k, v in raw.items() if not k.startswith("_")}

    gateway = MockModelGateway(mode=args.mode)
    result = RedRole(gateway).run(task)

    kind = "red_proposal" if "scenario" in result else "error_response"
    print(f"[{args.fixture} / mode={args.mode}] -> {kind}")
    print(json.dumps(result, indent=2, ensure_ascii=False))

    TEMP_OUT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    out_path = TEMP_OUT / f"{kind}_{args.mode}_{stamp}.json"
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
