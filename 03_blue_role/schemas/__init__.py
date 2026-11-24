"""Compatibility alias: ``schemas`` is now ``autosoc_blue.schemas``.

Kept so existing imports (``from schemas.models import ...``) keep working.
New code should import ``autosoc_blue.schemas``.
"""

import sys

from autosoc_blue import schemas as _real
from autosoc_blue.schemas import _loader, constants, errors, models, serializer, validation  # noqa: F401

for _name in ("_loader", "constants", "errors", "models", "serializer", "validation"):
    sys.modules[f"schemas.{_name}"] = getattr(_real, _name)
sys.modules[__name__] = _real
