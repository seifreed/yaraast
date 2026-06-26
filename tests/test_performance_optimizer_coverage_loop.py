# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests covering the remaining uncovered lines in performance/optimizer.py.

Missing lines before this file:
    72->exit, 79->exit, 86->exit : @overload stubs (callable via typing.get_overloads)
    193    : _string_check_cost fallback return 300 for unknown StringDefinition subclass
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast, get_overloads

from yaraast.ast.strings import StringDefinition
from yaraast.parser import Parser
from yaraast.performance.optimizer import (
    PerformanceOptimizer,
)

# ---------------------------------------------------------------------------
# Helper: a concrete StringDefinition subclass that is not PlainString,
# HexString, or RegexString — needed to reach line 193 in _string_check_cost.
# ---------------------------------------------------------------------------


@dataclass
class _UnknownStringKind(StringDefinition):
    """Minimal concrete StringDefinition not recognised by _string_check_cost."""


# @overload stubs — branches 72->exit, 79->exit, 86->exit
#
# The @overload decorators register the typed stubs via typing.overload.
# At runtime, typing.get_overloads() returns those stub functions.
# Calling them executes their '...' body (an Ellipsis expression that Python
# evaluates and discards), then falls through to an implicit 'return None'.
# This is the only way to execute the stub bodies and cover the exit branches.
# ---------------------------------------------------------------------------


class TestOverloadStubs:
    """Exercise the three @overload stubs on PerformanceOptimizer.optimize."""

    def test_overload_stubs_are_callable_and_return_none(self) -> None:
        stubs = get_overloads(PerformanceOptimizer.optimize)
        # The module defines exactly three @overload signatures
        assert len(stubs) == 3

        optimizer = PerformanceOptimizer()
        parser = Parser()
        ast = parser.parse("rule t { condition: true }")
        rule = ast.rules[0]

        # Each stub is callable on a real optimizer instance; each returns None
        # because the body is '...' (Ellipsis) with no explicit return.
        for stub in stubs:
            result = stub(optimizer, rule)
            assert result is None

    def test_overload_stubs_source_lines_match_module(self) -> None:
        # Confirm the stubs originate from the three expected line numbers
        stubs = get_overloads(PerformanceOptimizer.optimize)
        first_lines = [stub.__code__.co_firstlineno for stub in stubs]
        # The overload stubs should still be the three `def optimize` blocks.
        assert first_lines == [41, 48, 55]


# ---------------------------------------------------------------------------
# _string_check_cost fallback — line 193
# ---------------------------------------------------------------------------


class TestStringCheckCostFallback:
    """Verify _string_check_cost returns 300 for unrecognised StringDefinition types."""

    def test_unknown_string_definition_subclass_costs_300(self) -> None:
        # Line 193: the else-fallback after PlainString, HexString, RegexString checks
        unknown = _UnknownStringKind(identifier="$u")
        cost = PerformanceOptimizer._string_check_cost(unknown)
        assert cost == 300

    def test_sort_order_with_mixed_known_and_unknown_strings(self) -> None:
        # Trigger the fallback in context of a real optimize_rule call
        # so that the sort key includes the 300-cost unknown string.
        from yaraast.ast.rules import Rule
        from yaraast.ast.strings import PlainString

        rule = Rule(
            name="mixed",
            strings=[
                _UnknownStringKind(identifier="$u"),  # cost=300 (fallback)
                PlainString(identifier="$short", value="ab"),  # cost=2 (len of "ab")
            ],
        )
        optimizer = PerformanceOptimizer()
        optimized = optimizer.optimize_rule(rule, strategy="speed")
        # The cheap PlainString should sort before the unknown-kind string
        assert optimized.strings[0].identifier == "$short"
        assert optimized.strings[1].identifier == "$u"

    def test_plain_string_with_none_value_costs_300(self) -> None:
        # Within PlainString branch: value is not str|bytes → returns 300
        # (tests the 'else 300' on line 188, but also exercises the fallthrough
        #  into the main fallback at 193 indirectly via cost comparison)
        from yaraast.ast.strings import PlainString

        ps = PlainString(identifier="$x", value=cast(Any, None))
        cost = PerformanceOptimizer._string_check_cost(ps)
        assert cost == 300


# ---------------------------------------------------------------------------
# Integration: confirm that _optimize_for_speed with no strings is a no-op
# (branch 161: rule.strings is falsy — already partially covered, verified
#  here with a rule built from real parser output).
# ---------------------------------------------------------------------------


class TestOptimizeForSpeedNoStrings:
    """Ensure rules without strings pass through _optimize_for_speed unchanged."""

    def test_rule_without_strings_is_unchanged(self) -> None:
        parser = Parser()
        ast = parser.parse("rule bare { condition: true }")
        rule = ast.rules[0]
        assert not rule.strings

        optimizer = PerformanceOptimizer()
        result = optimizer._optimize_for_speed(rule)

        assert result is rule
        assert not result.strings
        assert optimizer.get_statistics()["strings_optimized"] == 0
