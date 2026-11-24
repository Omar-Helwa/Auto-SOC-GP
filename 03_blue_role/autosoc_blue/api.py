"""HTTP API (optional): ``pip install 'autosoc-blue[http]'``.

    POST /propose          body = blue_input   -> 200 blue_proposal
                                                  422 error_response (input / no safe edit)
    POST /propose?trace=1  -> 200 {"proposal": ..., "trace": ...}
    POST /propose?render=spl -> 200 {"blue_proposal": <unchanged>, "edited_rule": {"format", "text"}}
    POST /convert          body {"from": "sigma"|"spl", "to": "spl"|"sigma", "rule_text": "...", "index"?: "..."}
                           -> 200 {"format", "text", "notes"}   422 error_response
    GET  /health           -> {"status": "ok", ...}

Run:  python -m autosoc_blue serve --port 8080
 or:  uvicorn --factory autosoc_blue.api:create_app
"""

from __future__ import annotations

import os

from fastapi import Body, FastAPI
from fastapi.responses import JSONResponse

from . import __version__
from .core.engine import BlueEngine
from .core.errors import BlueError
from .factory import build_engine
from .schemas.errors import build_error_response
from .spl import SplError, convert_text


def create_app(engine: BlueEngine | None = None) -> FastAPI:
    engine = engine or build_engine()
    app = FastAPI(title="AutoSOC Blue role", version=__version__)

    @app.get("/health")
    def health() -> dict:
        return {
            "status": "ok",
            "version": __version__,
            "proposer": engine.proposer.name,
            "provider": os.environ.get("BLUE_MODEL_PROVIDER", "none"),
        }

    @app.post("/propose")
    def propose(blue_input: dict = Body(...), trace: bool = False, render: str | None = None):
        task_id = blue_input.get("task_id") if isinstance(blue_input, dict) else None
        try:
            result = engine.propose_with_trace(blue_input)
        except BlueError as exc:
            status = 422 if exc.category in ("validation", "missing_information") else 500
            body = build_error_response(exc.category, exc.message, task_id=task_id, details=exc.details)
            return JSONResponse(body, status_code=status)
        except Exception as exc:
            body = build_error_response("internal", f"unexpected error: {type(exc).__name__}", task_id=task_id)
            return JSONResponse(body, status_code=500)
        wrapped = None
        if render:
            try:
                wrapped = result.with_edited_rule(render)
            except BlueError as exc:
                body = build_error_response(exc.category, exc.message, task_id=task_id, details=exc.details)
                return JSONResponse(body, status_code=422)
        if trace:
            return {**(wrapped or {"proposal": result.proposal}), "trace": result.trace()}
        return wrapped or result.proposal

    @app.post("/convert")
    def convert(body: dict = Body(...)):
        src, dst, text = body.get("from"), body.get("to"), body.get("rule_text")
        if src not in ("sigma", "spl") or dst not in ("sigma", "spl") or not isinstance(text, str) or not text.strip():
            err = build_error_response(
                "validation", "convert needs 'from' and 'to' (sigma|spl) and a non-empty 'rule_text'")
            return JSONResponse(err, status_code=422)
        try:
            converted, notes = convert_text(text, src, dst, index=body.get("index"))
        except SplError as exc:
            err = build_error_response("validation", f"cannot convert: {exc.message}",
                                       details={"unsupported": exc.construct})
            return JSONResponse(err, status_code=422)
        return {"format": dst, "text": converted, "notes": notes}

    return app
