"""Tests to cover YARA-L optimizer paths (no mocks)."""

from __future__ import annotations

from yaraast.yaral.ast_nodes import (
    EventAssignment,
    EventStatement,
    EventVariable,
    TimeWindow,
    UDMFieldPath,
)
from yaraast.yaral.optimizer import YaraLOptimizer
from yaraast.yaral.parser import YaraLParser


def test_yaral_optimizer_basic() -> None:
    yaral_code = """
rule opt_rule {
    events:
        $e.metadata.event_type = "LOGIN"
        $e.principal.hostname = "host1"
    match:
        $hostname over 5m
    condition:
        #e > 1 and $e
}
"""
    parser = YaraLParser(yaral_code)
    ast = parser.parse()

    optimizer = YaraLOptimizer()
    optimized, stats = optimizer.optimize(ast)

    assert optimized is not None
    assert stats.rules_optimized >= 0


def test_yaral_optimizer_redundant_assignments() -> None:
    optimizer = YaraLOptimizer()
    event = EventVariable(name="$e")
    field = UDMFieldPath(parts=["metadata", "event_type"])
    stmt = EventStatement()
    stmt.event = event
    stmt.assignments = [
        EventAssignment(event_var=event, field_path=field, operator="=", value="LOGIN"),
        EventAssignment(event_var=event, field_path=field, operator="=", value="LOGIN"),
    ]

    optimized = optimizer._remove_redundant_assignments(stmt.assignments)

    assert len(optimized) == 1
    assert optimizer.stats.redundant_checks_removed >= 1


def test_yaral_optimizer_time_window() -> None:
    optimizer = YaraLOptimizer()
    window = TimeWindow(duration=3600, unit="s")
    optimized = optimizer._optimize_time_window(window)

    assert optimized.unit == "h"
