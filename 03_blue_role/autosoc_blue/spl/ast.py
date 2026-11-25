"""Tiny boolean tree shared by the SPL parser and the SPL renderer."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Leaf:
    field: str
    pattern: str  # value with '*' wildcards, already unescaped


@dataclass(frozen=True)
class And:
    items: tuple


@dataclass(frozen=True)
class Or:
    items: tuple


@dataclass(frozen=True)
class Not:
    item: object


def make_and(items) -> object:
    flat: list = []
    for it in items:
        flat.extend(it.items if isinstance(it, And) else [it])
    return flat[0] if len(flat) == 1 else And(tuple(flat))


def make_or(items) -> object:
    flat: list = []
    for it in items:
        flat.extend(it.items if isinstance(it, Or) else [it])
    return flat[0] if len(flat) == 1 else Or(tuple(flat))


def make_not(item) -> object:
    return item.item if isinstance(item, Not) else Not(item)
