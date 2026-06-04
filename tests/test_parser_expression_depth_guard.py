"""Regression tests for the expression nesting depth guard.

Pathologically nested expressions (deeply parenthesised conditions, nested for
bodies, etc.) previously drove the recursive descent parser past the interpreter
recursion limit and surfaced as an unhandled ``RecursionError``. The parser must
instead reject such input with a clean ``ParserError`` while still accepting
realistically nested rules.
"""

from __future__ import annotations

import sys

import pytest

from yaraast import Parser
from yaraast.parser._shared import ParserError, max_expression_depth


def _parse(src: str) -> object:
    return Parser().parse(src)


def test_deeply_nested_parentheses_raise_clean_error() -> None:
    depth = 5000
    src = "rule x { condition: " + "(" * depth + "true" + ")" * depth + " }"
    with pytest.raises(ParserError, match="expression nesting too deep"):
        _parse(src)


def test_deeply_nested_for_bodies_raise_clean_error() -> None:
    depth = 2000
    src = "rule x { condition: " + "for all i in (1..2) : ( " * depth + "true" + " )" * depth + " }"
    with pytest.raises(ParserError, match="expression nesting too deep"):
        _parse(src)


def test_no_recursion_error_across_all_depths_at_default_limit() -> None:
    limit = max_expression_depth()
    for depth in range(limit - 2, limit + 30):
        src = "rule x { condition: " + "(" * depth + "true" + ")" * depth + " }"
        try:
            _parse(src)
        except ParserError:
            pass
        except RecursionError:
            pytest.fail(f"RecursionError leaked at nesting depth {depth}")


def test_no_recursion_error_at_lowered_recursion_limit() -> None:
    original = sys.getrecursionlimit()
    sys.setrecursionlimit(200)
    try:
        limit = max_expression_depth()
        for depth in range(max(1, limit - 2), limit + 30):
            src = "rule x { condition: " + "(" * depth + "true" + ")" * depth + " }"
            try:
                _parse(src)
            except ParserError:
                pass
            except RecursionError:
                pytest.fail(f"RecursionError leaked at depth {depth}, limit 200")
    finally:
        sys.setrecursionlimit(original)


def test_reasonable_nesting_still_parses() -> None:
    src = "rule x { condition: " + "(" * 20 + "true" + ")" * 20 + " }"
    assert _parse(src) is not None


def test_deeper_nesting_allowed_when_recursion_limit_raised() -> None:
    original = sys.getrecursionlimit()
    sys.setrecursionlimit(20000)
    try:
        src = "rule x { condition: " + "(" * 500 + "true" + ")" * 500 + " }"
        assert _parse(src) is not None
    finally:
        sys.setrecursionlimit(original)


def test_parser_instance_recovers_depth_after_rejection() -> None:
    parser = Parser()
    deep = "rule x { condition: " + "(" * 5000 + "true" + ")" * 5000 + " }"
    with pytest.raises(ParserError):
        parser.parse(deep)
    # The shared instance must parse normal input afterwards with depth reset.
    assert parser.parse("rule y { condition: ((true)) }") is not None
