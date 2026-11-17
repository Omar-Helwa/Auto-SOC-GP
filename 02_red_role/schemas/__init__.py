"""Red role — local representation of the shared contracts (Epic B).

This package is the Red component's *local* view of the contracts in
``00_shared_contracts/`` plus its own input contract. It provides:

- ``constants``   : the closed vocabularies (families, actions, categories).
- ``validation``  : validate any dict against a contract schema (source of truth).
- ``models``      : typed dataclasses for red_input and red_proposal.
- ``errors``      : build contract-valid error_response payloads.
- ``serializer``  : turn a model into a validated, contract-valid dict / JSON.

Nothing here imports another member's implementation — only the shared
JSON Schema files. That satisfies the rule: "a member can validate their own
output without importing another member's implementation."
"""

from . import constants, validation, models, errors, serializer  # noqa: F401

__all__ = ["constants", "validation", "models", "errors", "serializer"]
