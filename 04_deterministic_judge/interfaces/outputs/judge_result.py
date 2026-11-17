from typing import Any

def serialize_result(result: dict[str, Any]):
    """Return a JSON-compatible result with no runtime-specific objects."""
    return result
