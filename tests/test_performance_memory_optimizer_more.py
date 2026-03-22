"""More tests for memory optimizer (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.parser import Parser
from yaraast.performance.memory_optimizer import MemoryOptimizer


def _parse_yara(code: str):
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

    optimizer.track_object(ast)
    stats_before = optimizer.get_statistics()
    assert stats_before["total_objects"] >= 1

    optimized = optimizer.optimize(ast)
    assert optimized is not ast  # optimizer returns a new copy, not the original

    stats = optimizer.get_statistics()
    assert stats["nodes_processed"] >= 1
    assert stats["string_pool_size"] >= 1

    mem_stats = optimizer.get_memory_stats()
    assert mem_stats.total_objects >= 1

    optimizer.clear_caches()
    stats_after = optimizer.get_statistics()
    assert stats_after["string_pool_size"] == 0


def test_memory_optimizer_context_and_cleanup() -> None:
    optimizer = MemoryOptimizer(enable_tracking=True)
    with optimizer.memory_managed_context():
        optimizer.track_object({"x": 1})

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

    ast1 = optimizer.create_memory_efficient_ast()
    optimizer.return_ast_to_pool(ast1)
    ast2 = optimizer.create_memory_efficient_ast()
    assert ast2 is ast1
