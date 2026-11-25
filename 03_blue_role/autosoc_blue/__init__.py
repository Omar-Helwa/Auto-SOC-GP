"""AutoSOC Blue role: propose small, safe edits to a detection rule.

Standalone package. It imports nothing from other AutoSOC folders. See the
README in ``03_blue_role/`` for the architecture and usage.
"""

from .core.engine import BlueEngine, BlueResult  # noqa: F401
from .core.errors import BlueError, InputError, NoProposalError  # noqa: F401
from .factory import build_engine  # noqa: F401
from .role import BlueRole  # noqa: F401

__version__ = "0.1.0"
