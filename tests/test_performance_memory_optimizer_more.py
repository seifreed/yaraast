"""More tests for memory optimizer (no mocks)."""

from __future__ import annotations

from textwrap import dedent
from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.parser import Parser
from yaraast.performance.memory_optimizer import MemoryOptimizer


def _parse_yara(code: str) -> YaraFile:
    parser = Parser()
    return parser.parse(dedent(code))


def test_memory_optimizer_basic_and_stats() -> None:
    code = """
    import "pe"
    rule mem_rule : tag1 {
        strings:
            $a = "abc"
            $b = "abc"
        condition:
            $a and pe.number_of_sections > 0
    }
    """
    ast = _parse_yara(code)
    optimizer = MemoryOptimizer(enable_tracking=True)
    stats_before = optimizer.get_statistics()
    assert stats_before["total_objects"] >= 0

    optimized = optimizer.optimize(ast)
    assert optimized is not ast  # optimizer returns a new copy, not the original

    stats = optimizer.get_statistics()
    assert stats["nodes_processed"] >= 1
    assert stats["string_pool_size"] >= 1
    assert "memory_saved" not in stats

    mem_stats = optimizer.get_memory_stats()
    assert mem_stats.total_objects >= 0
    assert not hasattr(mem_stats, "strings_pooled")


def test_memory_optimizer_context_and_cleanup() -> None:
    optimizer = MemoryOptimizer(enable_tracking=True)
    with optimizer.memory_managed_context():
        _ = {"x": 1}

    mem_stats = optimizer.get_memory_stats()
    assert mem_stats.total_objects >= 0

    cleaned = optimizer.force_cleanup()
    assert isinstance(cleaned, int)


def test_memory_optimizer_recommendations_and_pool() -> None:
    optimizer = MemoryOptimizer()
    rec_small = optimizer.optimize_for_large_collection(10)
    rec_medium = optimizer.optimize_for_large_collection(200)
    rec_large = optimizer.optimize_for_large_collection(2000)

    assert rec_small["batch_size"] <= rec_medium["batch_size"]
    assert rec_large["use_streaming"] is True
    assert rec_large["enable_pooling"] is True


def test_memory_optimizer_rejects_invalid_numeric_configuration() -> None:
    with pytest.raises(TypeError, match="memory_limit_mb must be an integer"):
        MemoryOptimizer(memory_limit_mb=cast(Any, True))

    with pytest.raises(TypeError, match="gc_threshold must be an integer"):
        MemoryOptimizer(gc_threshold=cast(Any, True))

    with pytest.raises(TypeError, match="size must be an integer"):
        MemoryOptimizer().optimize_for_large_collection(cast(Any, True))

    with pytest.raises(ValueError, match="memory_limit_mb must be at least 1"):
        MemoryOptimizer(memory_limit_mb=0)

    with pytest.raises(ValueError, match="gc_threshold must be at least 1"):
        MemoryOptimizer(gc_threshold=0)

    optimizer = MemoryOptimizer()
    with pytest.raises(ValueError, match="size must be at least 0"):
        optimizer.optimize_for_large_collection(-1)
