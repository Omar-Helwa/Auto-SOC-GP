"""Scenario families and bounds enforcement (Epic C)."""

from .families import FAMILY_DESCRIPTIONS, describe_families  # noqa: F401
from .bounds import check_bounds, BoundsViolation  # noqa: F401

__all__ = ["FAMILY_DESCRIPTIONS", "describe_families", "check_bounds", "BoundsViolation"]
