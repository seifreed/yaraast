"""Helpers for memory optimization."""

from __future__ import annotations

from dataclasses import dataclass
import gc
from typing import Any


def pooled_value(pool: dict[str, str], value: str) -> str:
    pooled = pool.get(value)
    if pooled is None:
        pool[value] = value
        return value
    return pooled


def maybe_collect(aggressive: bool) -> None:
    if aggressive:
        gc.collect()


def clear_tracking(tracked_objects: list[Any]) -> None:
    tracked_objects.clear()
    gc.collect()


@dataclass
class MemoryStats:
    total_objects: int
    nodes_processed: int
    strings_pooled: int
