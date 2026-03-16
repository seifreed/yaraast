"""Runtime helpers for MemoryOptimizer."""

from __future__ import annotations

import gc
import weakref
from contextlib import contextmanager
from typing import Any

from yaraast.performance.memory_helpers import MemoryStats, clear_tracking, maybe_collect


def init_optimizer_state(optimizer) -> None:
    optimizer._cache = weakref.WeakValueDictionary()
    optimizer._string_pool = {}
    optimizer._tracked_objects = []
    optimizer._ast_pool = []
    optimizer._stats = {
        "nodes_processed": 0,
        "strings_pooled": 0,
        "memory_saved": 0,
        "total_objects": 0,
    }


def get_memory_usage() -> dict[str, Any]:
    import os

    import psutil

    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    return {
        "rss_mb": mem_info.rss / 1024 / 1024,
        "vms_mb": mem_info.vms / 1024 / 1024,
        "percent": process.memory_percent(),
        "available_mb": psutil.virtual_memory().available / 1024 / 1024,
    }


def clear_caches(optimizer) -> None:
    optimizer._cache.clear()
    optimizer._string_pool.clear()
    gc.collect()


def get_statistics(optimizer) -> dict[str, Any]:
    return {
        **optimizer._stats,
        "string_pool_size": len(optimizer._string_pool),
        "cache_size": len(optimizer._cache),
    }


def memory_managed_context(optimizer):
    @contextmanager
    def context():
        try:
            yield
        finally:
            if optimizer.enable_tracking:
                clear_tracking(optimizer._tracked_objects)
            else:
                gc.collect()

    return context()


def get_memory_stats(optimizer):
    return MemoryStats(
        total_objects=optimizer._stats.get("total_objects", 0),
        nodes_processed=optimizer._stats.get("nodes_processed", 0),
        strings_pooled=optimizer._stats.get("strings_pooled", 0),
    )


def force_cleanup(optimizer) -> int:
    clear_tracking(optimizer._tracked_objects)
    optimizer._stats["total_objects"] = 0
    return gc.collect()


def create_memory_efficient_ast(optimizer):
    from yaraast.ast.base import YaraFile

    if optimizer._ast_pool:
        return optimizer._ast_pool.pop()
    return YaraFile(imports=[], includes=[], rules=[])


def batch_process_with_memory_limit(
    optimizer, items: list[Any], processor: Any, batch_size: int = 10
):
    for index in range(0, len(items), batch_size):
        batch = items[index : index + batch_size]
        results = [processor(item) for item in batch]
        yield results
        if index % (optimizer.gc_threshold * batch_size) == 0:
            gc.collect()


def maybe_post_optimize_collect(optimizer) -> None:
    maybe_collect(optimizer.aggressive)
