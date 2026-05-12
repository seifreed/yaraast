"""Runtime helpers for MemoryOptimizer."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager
import gc
from typing import Any
import weakref

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.performance.memory_helpers import MemoryStats, clear_tracking, maybe_collect


def init_optimizer_state(optimizer: Any) -> None:
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


def clear_caches(optimizer: Any) -> None:
    optimizer._cache.clear()
    optimizer._string_pool.clear()
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
        strings_pooled=optimizer._stats.get("strings_pooled", 0),
    )


def force_cleanup(optimizer: Any) -> int:
    clear_tracking(optimizer._tracked_objects)
    optimizer._stats["total_objects"] = 0
    return gc.collect()


def create_memory_efficient_ast(optimizer: Any) -> ASTNode:
    if optimizer._ast_pool:
        return optimizer._ast_pool.pop()
    return YaraFile(imports=[], includes=[], rules=[])


def batch_process_with_memory_limit[Item, Result](
    optimizer: Any,
    items: Sequence[Item],
    processor: Callable[[Item], Result],
    batch_size: int = 10,
) -> Iterator[list[Result]]:
    if batch_size < 1:
        msg = "batch_size must be at least 1"
        raise ValueError(msg)

    for index in range(0, len(items), batch_size):
        batch = items[index : index + batch_size]
        results = [processor(item) for item in batch]
        yield results
        if index % (optimizer.gc_threshold * batch_size) == 0:
            gc.collect()


def maybe_post_optimize_collect(optimizer: Any) -> None:
    maybe_collect(optimizer.aggressive)
