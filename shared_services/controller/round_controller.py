"""Public shared-services entry point for the Orchestrator round workflow."""

from __future__ import annotations

import sys
from importlib import import_module
from pathlib import Path
from typing import Any, Mapping, Optional

from ..datastore.repository import MongoRepository

REPO_ROOT = Path(__file__).resolve().parents[2]
ORCHESTRATOR_ROOT = REPO_ROOT / "01_orchestrator"


def _create_workflow(repository: MongoRepository, services: Any, validator: Any = None) -> Any:
    orchestrator_path = str(ORCHESTRATOR_ROOT)
    if orchestrator_path not in sys.path:
        sys.path.append(orchestrator_path)

    workflow_factory = import_module("workflow")
    return workflow_factory.create_mongo_workflow(
        repository, services, validator=validator
    )


class RoundController:
    """Keep one public controller while delegating lifecycle policy to 01_orchestrator."""

    def __init__(
        self,
        repository: MongoRepository,
        services: Any,
        *,
        validator: Optional[Any] = None,
    ) -> None:
        self.repository = repository
        self.workflow = _create_workflow(repository, services, validator)

    def run_round(self, round_request: Mapping[str, Any]) -> Any:
        """Validate, persist, and run a complete round in the prescribed order."""
        return self.workflow.run_round(round_request)

    def run_open_round(self, round_id: str) -> Any:
        """Resume the next step of a persisted nonterminal round."""
        return self.workflow.run_open_round(round_id)
