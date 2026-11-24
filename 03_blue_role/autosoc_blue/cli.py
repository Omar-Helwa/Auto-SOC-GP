"""Command line: ``python -m autosoc_blue propose|validate|serve``.

Exit codes: 0 ok, 1 Blue answered with an error_response (or the file is
invalid), 2 usage / configuration problem.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .adapters.gateways.factory import PROVIDERS, GatewayConfigError
from .core.errors import BlueError
from .factory import build_engine
from .schemas import validation
from .schemas.errors import build_error_response


def _load_json(path: str):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"error: file not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: {path} is not valid JSON: {exc}") from None


def _strip_helpers(data):
    # The contract examples carry documentation keys that start with "_".
    return {k: v for k, v in data.items() if not k.startswith("_")} if isinstance(data, dict) else data


def _emit(payload: dict, out: str | None) -> None:
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if out:
        Path(out).write_text(text + "\n", encoding="utf-8")
        print(f"written: {out}", file=sys.stderr)
    else:
        print(text)


def cmd_propose(args) -> int:
    data = _strip_helpers(_load_json(args.input))
    try:
        engine = build_engine(args.provider, allow_partial=True if args.allow_partial else None)
    except GatewayConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        result = engine.propose_with_trace(data)
    except BlueError as exc:
        task_id = data.get("task_id") if isinstance(data, dict) else None
        _emit(build_error_response(exc.category, exc.message, task_id=task_id, details=exc.details), args.out)
        print(f"blue: no proposal ({exc.category}): {exc.message}", file=sys.stderr)
        return 1
    _emit(result.proposal, args.out)
    if args.trace:
        for a in result.trace()["attempts"]:
            print(f"trace: {a['proposer']} attempt {a['attempt']}: {a['status']} {a['reasons']}", file=sys.stderr)
    print(f"blue: proposal ready (proposer: {result.proposer_used})", file=sys.stderr)
    return 0


def cmd_validate(args) -> int:
    data = _strip_helpers(_load_json(args.input))
    kind = args.kind
    if kind == "auto":
        kind = "proposal" if isinstance(data, dict) and "edits" in data else "input"
    result = validation.validate_blue_proposal(data) if kind == "proposal" else validation.validate_blue_input(data)
    if result.ok:
        print(f"valid blue_{kind}")
        return 0
    print(f"INVALID blue_{kind}:")
    for e in result.errors:
        print(f"  - {e.path}: {e.message}")
    return 1


def cmd_serve(args) -> int:
    try:
        import uvicorn

        from .api import create_app
    except ImportError:
        print("error: the HTTP API needs the extra dependencies: pip install 'autosoc-blue[http]'", file=sys.stderr)
        return 2
    try:
        app = create_app(build_engine(args.provider))
    except GatewayConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="autosoc_blue", description="AutoSOC Blue role")
    p.add_argument("--version", action="version", version=f"autosoc_blue {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    pr = sub.add_parser("propose", help="blue_input.json -> blue_proposal.json")
    pr.add_argument("--input", required=True, help="path to a blue_input JSON file")
    pr.add_argument("--provider", choices=PROVIDERS, default=None,
                    help="none = deterministic only (default, or env BLUE_MODEL_PROVIDER)")
    pr.add_argument("--out", help="write the result here instead of stdout")
    pr.add_argument("--trace", action="store_true", help="print the attempts (proposer, status, reasons) to stderr")
    pr.add_argument("--allow-partial", action="store_true",
                    help="accept a proposal that removes only some of the false positives")
    pr.set_defaults(func=cmd_propose)

    va = sub.add_parser("validate", help="check a blue_input or blue_proposal file against its contract")
    va.add_argument("--input", required=True)
    va.add_argument("--kind", choices=("auto", "input", "proposal"), default="auto")
    va.set_defaults(func=cmd_validate)

    sv = sub.add_parser("serve", help="run the HTTP API (needs the [http] extra)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8080)
    sv.add_argument("--provider", choices=PROVIDERS, default=None)
    sv.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
