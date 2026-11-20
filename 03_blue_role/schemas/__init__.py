"""Blue role: local representation of the shared contracts.

- ``constants``  : closed vocabularies (operations, modifiers, categories).
- ``validation`` : validate any dict against a contract schema (source of truth).
- ``models``     : typed dataclasses for blue_input and blue_proposal.
- ``errors``     : build contract-valid error_response payloads.
- ``serializer`` : turn a model into a validated, contract-valid dict / JSON.

Nothing here imports another member's implementation, only the shared JSON
Schema files.
"""

from . import constants, errors, models, serializer, validation  # noqa: F401

__all__ = ["constants", "validation", "models", "errors", "serializer"]
