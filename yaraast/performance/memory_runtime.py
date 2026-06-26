"""Runtime helpers for MemoryOptimizer."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
import gc
from typing import Any
import weakref

from yaraast.performance.memory_helpers import MemoryStats, clear_tracking, maybe_collect


def init_optimizer_state(optimizer: Any) -> None:
    optimizer._cache = weakref.WeakValueDictionary()
    optimizer._string_pool = {}
    optimizer._tracked_objects = []
    optimizer._ast_pool = []
    optimizer._stats = {
        "nodes_processed": 0,
        "strings_pooled": 0,
        "total_objects": 0,
    }


def clear_caches(optimizer: Any) -> None:
    optimizer._cache.clear()
    optimizer._string_pool.clear()
    optimizer._ast_pool.clear()
    gc.collect()


def get_statistics(optimizer: Any) -> dict[str, Any]:
    return {
        **optimizer._stats,
        "string_pool_size": len(optimizer._string_pool),
        "cache_size": len(optimizer._cache),
    }


def memory_managed_context(optimizer: Any) -> AbstractContextManager[None]:
    @contextmanager
    def context() -> Iterator[None]:
        try:
            yield
        finally:
            if optimizer.enable_tracking:
                clear_tracking(optimizer._tracked_objects)
            else:
                gc.collect()

    return context()


def get_memory_stats(optimizer: Any) -> MemoryStats:
    return MemoryStats(
        total_objects=optimizer._stats.get("total_objects", 0),
        nodes_processed=optimizer._stats.get("nodes_processed", 0),
    )


def force_cleanup(optimizer: Any) -> int:
    clear_tracking(optimizer._tracked_objects)
    optimizer._stats["total_objects"] = 0
    return gc.collect()


def maybe_post_optimize_collect(optimizer: Any) -> None:
    maybe_collect(optimizer.aggressive)
