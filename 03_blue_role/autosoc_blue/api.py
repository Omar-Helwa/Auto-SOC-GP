"""HTTP API (optional): ``pip install 'autosoc-blue[http]'``.

    POST /propose          body = blue_input   -> 200 blue_proposal
                                                  422 error_response (input / no safe edit)
    POST /propose?trace=1  -> 200 {"proposal": ..., "trace": ...}
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
    def propose(blue_input: dict = Body(...), trace: bool = False):
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
        if trace:
            return {"proposal": result.proposal, "trace": result.trace()}
        return result.proposal

    return app
