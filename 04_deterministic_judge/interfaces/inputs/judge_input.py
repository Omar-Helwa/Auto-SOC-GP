from dataclasses import dataclass
from typing import Any, Mapping

@dataclass(frozen=True)
class JudgeInput:
    """Validated shape-independent wrapper around an assembled judge input."""

    raw: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]):
        return cls(raw=value)
