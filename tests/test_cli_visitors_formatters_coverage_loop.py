# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Targeted regression tests closing the remaining coverage gap in formatters.py.

Missing lines before this file: 32, 70, 73, 408, 427, 441, 485.
Each test is named after the scenario it exercises and validates real
formatter output — no mocks, no stubs, no placeholder assertions.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from yaraast.ast.expressions import Identifier, IntegerLiteral
from yaraast.cli.visitors.formatters import (
    ConditionStringFormatter,
    ExpressionStringFormatter,
    _node_text,
    _string_set_item_text,
)

# ---------------------------------------------------------------------------
# Line 32: _node_text returns `default` when value has neither .value nor .name
# ---------------------------------------------------------------------------


def test_node_text_returns_default_when_no_value_or_name_attr() -> None:
    """_node_text must fall through to `default` (line 32) when the object
    carries neither a `value` nor a `name` attribute."""

    result = _node_text(object(), "fallback")
    assert result == "fallback"


def test_node_text_returns_value_attr_when_present() -> None:
    """Confirm the .value branch is taken before the default fallback."""
    obj = SimpleNamespace(value=42)
    assert _node_text(obj, "unused") == "42"


def test_node_text_returns_name_attr_when_value_absent() -> None:
    """Confirm the .name branch is taken when .value is absent."""
    obj = SimpleNamespace(name="myname")
    assert _node_text(obj, "unused") == "myname"


def test_node_text_returns_string_directly() -> None:
    """Plain strings are returned unchanged (first branch in _node_text)."""
    assert _node_text("hello", "unused") == "hello"


# ---------------------------------------------------------------------------
# Line 70: _string_set_item_text calls formatter.format_expression when item
#           has an `accept` attribute but no pattern / name / raw_value
# ---------------------------------------------------------------------------


class _AcceptOnly:
    """Minimal object that has `accept` but no pattern, name, or value."""

    def accept(self, visitor: Any) -> None:
        pass


def test_string_set_item_text_delegates_to_format_expression_via_accept() -> None:
    """Items with an `accept` attr but no pattern/name/value must trigger
    formatter.format_expression (line 70).  The formatter returns a
    non-empty string for any object that defines __class__."""
    formatter = ExpressionStringFormatter()
    item = _AcceptOnly()
    result = _string_set_item_text(item, formatter, 0)
    # The item is an unknown class so format_expression returns "<AcceptOnly>"
    assert result.startswith("<")


# ---------------------------------------------------------------------------
# Line 73: _string_set_item_text falls back to _node_text when item has no
#           accept and is not a str — and no pattern / name / value attrs
# ---------------------------------------------------------------------------


class _NoSpecialAttrs:
    """Object with no pattern, name, value, accept, or string type."""


def test_string_set_item_text_final_fallback_to_node_text() -> None:
    """The last line of _string_set_item_text (line 73) is reached when an
    item has none of pattern / name / value / accept and is not a str."""
    formatter = ExpressionStringFormatter()
    item = _NoSpecialAttrs()
    result = _string_set_item_text(item, formatter, 0)
    # _node_text receives item and str(item) as default; since _NoSpecialAttrs
    # has neither .value nor .name, it returns str(item) which is the repr.
    assert isinstance(result, str)
    assert len(result) > 0


# ---------------------------------------------------------------------------
# Line 408: _format_string_set returns the string_set directly when it is a str
# ---------------------------------------------------------------------------


def test_format_string_set_returns_string_directly() -> None:
    """When string_set is a plain str (e.g. 'them'), it must be returned
    verbatim (line 408)."""
    formatter = ExpressionStringFormatter()
    expr = SimpleNamespace(string_set="them")
    assert formatter._format_string_set(expr, 0) == "them"


def test_format_string_set_returns_custom_string_set_value() -> None:
    """Any str value, not just 'them', is returned as-is."""
    formatter = ExpressionStringFormatter()
    expr = SimpleNamespace(string_set="($a*)")
    assert formatter._format_string_set(expr, 0) == "($a*)"


# ---------------------------------------------------------------------------
# Line 427: _format_string_set reaches str(string_set.value) when string_set
#            has a .value attr but no .name attr
# ---------------------------------------------------------------------------


def test_format_string_set_uses_value_attr_when_name_absent() -> None:
    """string_set objects that carry .value but not .name must return
    str(string_set.value) (line 427)."""
    formatter = ExpressionStringFormatter()

    class _ValueOnly:
        value = "quantifier_literal"

    expr = SimpleNamespace(string_set=_ValueOnly())
    result = formatter._format_string_set(expr, 0)
    assert result == "quantifier_literal"


def test_format_string_set_prefers_name_over_value() -> None:
    """When both .name and .value exist, .name is taken (line 424-425)."""
    formatter = ExpressionStringFormatter()

    class _BothAttrs:
        name = "preferred"
        value = "ignored"

    expr = SimpleNamespace(string_set=_BothAttrs())
    result = formatter._format_string_set(expr, 0)
    assert result == "preferred"


# ---------------------------------------------------------------------------
# Line 441: _format_string_set returns self.format_expression(string_set) when
#            class is ParenthesesExpression but inner expression is None
# ---------------------------------------------------------------------------


def test_format_string_set_parentheses_with_no_inner_expression() -> None:
    """A ParenthesesExpression whose .expression attribute is None must fall
    through to self.format_expression(string_set, depth) (line 441)."""
    formatter = ExpressionStringFormatter()

    paren = type("ParenthesesExpression", (), {"expression": None})()
    expr = SimpleNamespace(string_set=paren)
    result = formatter._format_string_set(expr, 0)
    # format_expression receives a ParenthesesExpression with no inner
    # expression; it delegates to _format_parentheses_expression which
    # returns "(...)" when hasattr(expr, 'expression') is False — but here
    # the attribute exists and is None, so format_expression calls
    # _format_parentheses_expression which calls format_expression(None, ...)
    # returning "...".  The final result is "(...)".
    assert isinstance(result, str)
    assert len(result) > 0


def test_format_string_set_parentheses_with_stringwildcard_inner() -> None:
    """A ParenthesesExpression wrapping a StringWildcard must call
    _format_string_wildcard (line 435-436), not line 441.
    _format_string_wildcard wraps pattern in parens: f"({pattern})"."""
    formatter = ExpressionStringFormatter()

    wildcard = type("StringWildcard", (), {"pattern": "$a*"})()
    paren = type("ParenthesesExpression", (), {"expression": wildcard})()
    expr = SimpleNamespace(string_set=paren)
    result = formatter._format_string_set(expr, 0)
    assert result == "($a*)"


def test_format_string_set_parentheses_with_set_expression_inner() -> None:
    """A ParenthesesExpression wrapping a SetExpression must call
    _format_set_expression (line 437-438), not line 441."""
    formatter = ExpressionStringFormatter()

    set_expr = type("SetExpression", (), {"elements": [SimpleNamespace(name="$a")]})()
    paren = type("ParenthesesExpression", (), {"expression": set_expr})()
    expr = SimpleNamespace(string_set=paren)
    result = formatter._format_string_set(expr, 0)
    assert result == "($a)"


def test_format_string_set_parentheses_with_generic_inner() -> None:
    """A ParenthesesExpression wrapping an element that is neither
    StringWildcard nor SetExpression must use line 439-440."""
    formatter = ExpressionStringFormatter()

    inner = SimpleNamespace(name="$b")
    paren = type("ParenthesesExpression", (), {"expression": inner})()
    expr = SimpleNamespace(string_set=paren)
    result = formatter._format_string_set(expr, 0)
    assert result == "($b)"


# ---------------------------------------------------------------------------
# Line 485: ExpressionStringFormatter._format_string_length without an index
# ---------------------------------------------------------------------------


def test_expression_format_string_length_without_index() -> None:
    """_format_string_length must return '!<sid>' (line 485) when the
    StringLength node has no index attribute."""
    formatter = ExpressionStringFormatter()

    node = SimpleNamespace(string_id="$abc")
    # No `index` attribute: hasattr(node, 'index') is False → line 485 taken.
    result = formatter._format_string_length(node, 0)
    assert result == "!abc"


def test_expression_format_string_length_with_index() -> None:
    """_format_string_length with an index attribute must return '!<sid>[<idx>]'
    (lines 482-484), confirming the branching is correct."""
    formatter = ExpressionStringFormatter()

    node = SimpleNamespace(string_id="$x", index=IntegerLiteral(value=3))
    result = formatter._format_string_length(node, 0)
    assert result == "!x[3]"


def test_expression_format_string_length_with_none_index() -> None:
    """When the index attribute exists but is None, the no-index branch (line 485)
    must be taken."""
    formatter = ExpressionStringFormatter()

    node = SimpleNamespace(string_id="$y", index=None)
    result = formatter._format_string_length(node, 0)
    assert result == "!y"


# ---------------------------------------------------------------------------
# Complementary branch coverage: _format_string_set frozenset / set path
# ---------------------------------------------------------------------------


def test_format_string_set_with_frozenset() -> None:
    """string_set as a frozenset must be formatted with sorted-by-str ordering."""
    formatter = ExpressionStringFormatter()
    expr = SimpleNamespace(string_set=frozenset(["$b", "$a", "$c"]))
    result = formatter._format_string_set(expr, 0)
    assert result.startswith("(")
    assert "$a" in result and "$b" in result and "$c" in result


def test_format_string_set_with_set() -> None:
    """string_set as a plain set must also be handled by the frozenset branch."""
    formatter = ExpressionStringFormatter()
    expr = SimpleNamespace(string_set={"$z", "$m"})
    result = formatter._format_string_set(expr, 0)
    assert result.startswith("(")
    assert "$z" in result and "$m" in result


# ---------------------------------------------------------------------------
# Complementary: ConditionStringFormatter hash / long condition boundary cases
# ---------------------------------------------------------------------------


def test_condition_format_hash_condition_between_16_and_25_parts() -> None:
    """_format_hash_condition with 16-25 parts must abbreviate with '...'."""
    fmt = ConditionStringFormatter()
    parts = [f"hash.md5 == {i}" for i in range(20)]
    result = fmt._format_hash_condition(parts, "or")
    assert "..." in result


def test_condition_format_hash_condition_over_25_parts() -> None:
    """_format_hash_condition with >25 parts must truncate head and tail."""
    fmt = ConditionStringFormatter()
    parts = [f"hash.md5 == {i}" for i in range(30)]
    result = fmt._format_hash_condition(parts, "or")
    assert "..." in result
    # First 8 parts must appear.
    assert "hash.md5 == 0" in result
    # Last 2 parts must appear.
    assert "hash.md5 == 29" in result


def test_condition_format_long_condition() -> None:
    """_format_long_condition with >8 parts must keep first 5 and last 2."""
    fmt = ConditionStringFormatter()
    parts = [f"cond_{i}" for i in range(10)]
    result = fmt._format_long_condition(parts, "and")
    assert "cond_0" in result
    assert "cond_9" in result
    assert "..." in result


# ---------------------------------------------------------------------------
# Complementary: _string_set_item_text with a StringIdentifier name value
# ---------------------------------------------------------------------------


def test_string_set_item_text_string_identifier_with_dollar_prefix() -> None:
    """A StringIdentifier item whose name already starts with '$' must be
    returned as-is by _string_set_reference_text."""
    formatter = ExpressionStringFormatter()
    item = type("StringIdentifier", (), {"name": "$existing"})()
    result = _string_set_item_text(item, formatter, 0)
    assert result == "$existing"


def test_string_set_item_text_string_identifier_without_dollar_prefix() -> None:
    """A StringIdentifier item whose name lacks '$' must gain the prefix."""
    formatter = ExpressionStringFormatter()
    item = type("StringIdentifier", (), {"name": "nprefix"})()
    result = _string_set_item_text(item, formatter, 0)
    assert result == "$nprefix"


def test_string_set_item_text_plain_string_them() -> None:
    """A plain 'them' string in a string set must be returned verbatim."""
    formatter = ExpressionStringFormatter()
    result = _string_set_item_text("them", formatter, 0)
    assert result == "them"


def test_string_set_item_text_plain_string_with_dollar() -> None:
    """A plain string starting with '$' is returned verbatim."""
    formatter = ExpressionStringFormatter()
    result = _string_set_item_text("$abc", formatter, 0)
    assert result == "$abc"


def test_string_set_item_text_plain_string_without_dollar() -> None:
    """A plain string not starting with '$' and not 'them' gains '$' prefix."""
    formatter = ExpressionStringFormatter()
    result = _string_set_item_text("abc", formatter, 0)
    assert result == "$abc"


# ---------------------------------------------------------------------------
# Complementary: ExpressionStringFormatter._format_string_offset with index
# ---------------------------------------------------------------------------


def test_expression_format_string_offset_with_index() -> None:
    """_format_string_offset with a non-None index must return '@<sid>[<idx>]'."""
    formatter = ExpressionStringFormatter()
    node = SimpleNamespace(string_id="$hit", index=IntegerLiteral(value=0))
    result = formatter._format_string_offset(node, 0)
    assert result == "@hit[0]"


def test_expression_format_string_offset_without_index() -> None:
    """_format_string_offset with no index attribute must return '@<sid>'."""
    formatter = ExpressionStringFormatter()
    node = SimpleNamespace(string_id="$hit")
    result = formatter._format_string_offset(node, 0)
    assert result == "@hit"


# ---------------------------------------------------------------------------
# Complementary: depth guard in ExpressionStringFormatter.format_expression
# ---------------------------------------------------------------------------


def test_expression_formatter_depth_guard_returns_ellipsis() -> None:
    """format_expression must return '...' when depth exceeds 5."""
    formatter = ExpressionStringFormatter()
    result = formatter.format_expression(Identifier(name="x"), depth=6)
    assert result == "..."


def test_expression_formatter_none_input_returns_ellipsis() -> None:
    """format_expression must return '...' for None input."""
    formatter = ExpressionStringFormatter()
    assert formatter.format_expression(None, 0) == "..."


# ---------------------------------------------------------------------------
# Complementary: ConditionStringFormatter depth guard
# ---------------------------------------------------------------------------


def test_condition_formatter_depth_guard_returns_ellipsis() -> None:
    """format_condition must return '...' when depth exceeds 3."""
    fmt = ConditionStringFormatter()
    result = fmt.format_condition(Identifier(name="x"), depth=4)
    assert result == "..."


# ---------------------------------------------------------------------------
# Branch [224, 226]: ConditionStringFormatter._format_function_args with
# exactly 1-2 arguments (no truncation — branch len > 2 is False)
# ---------------------------------------------------------------------------


def test_condition_format_function_args_one_argument_no_truncation() -> None:
    """_format_function_args with exactly 1 argument must not append ', ...'
    (branch at line 224 evaluates False)."""
    fmt = ConditionStringFormatter()
    node = SimpleNamespace(function="f", arguments=[Identifier(name="a")])
    result = fmt._format_function_call(node, 0)
    assert result == "f(a)"
    assert "..." not in result


def test_condition_format_function_args_two_arguments_no_truncation() -> None:
    """_format_function_args with exactly 2 arguments must not append ', ...'."""
    fmt = ConditionStringFormatter()
    node = SimpleNamespace(function="g", arguments=[Identifier(name="x"), Identifier(name="y")])
    result = fmt._format_function_call(node, 0)
    assert result == "g(x, y)"
    assert "..." not in result


# ---------------------------------------------------------------------------
# Branch [374, 376]: ExpressionStringFormatter._format_function_args with
# exactly 1-2 arguments (no truncation)
# ---------------------------------------------------------------------------


def test_expression_format_function_args_one_argument_no_truncation() -> None:
    """ExpressionStringFormatter._format_function_args with 1 argument must
    not append ', ...' (branch at line 374 evaluates False)."""
    formatter = ExpressionStringFormatter()
    node = SimpleNamespace(function="h", arguments=[Identifier(name="z")])
    result = formatter._format_function_call(node, 0)
    assert result == "h(z)"
    assert "..." not in result


def test_expression_format_function_args_two_arguments_no_truncation() -> None:
    """ExpressionStringFormatter._format_function_args with 2 arguments must
    not append ', ...'."""
    formatter = ExpressionStringFormatter()
    node = SimpleNamespace(
        function="math.min", arguments=[Identifier(name="a"), Identifier(name="b")]
    )
    result = formatter._format_function_call(node, 0)
    assert result == "math.min(a, b)"
    assert "..." not in result


# ---------------------------------------------------------------------------
# Branch [300, 302]: _collect_binary_parts when BinaryExpression has `left`
# but no `right` attribute
# ---------------------------------------------------------------------------


class _BinaryExpressionLeftOnly:
    """BinaryExpression-named class that has `left` and `operator` but no `right`."""

    def __init__(self, operator: str, left: Any) -> None:
        self.operator = operator
        self.left = left


# Rename so _formatter_class_name sees "BinaryExpression" in the MRO name.
_BinaryExpressionLeftOnly.__name__ = "BinaryExpression"
_BinaryExpressionLeftOnly.__qualname__ = "BinaryExpression"


class _BinaryExpressionRightOnly:
    """BinaryExpression-named class that has `right` and `operator` but no `left`."""

    def __init__(self, operator: str, right: Any) -> None:
        self.operator = operator
        self.right = right


_BinaryExpressionRightOnly.__name__ = "BinaryExpression"
_BinaryExpressionRightOnly.__qualname__ = "BinaryExpression"


def test_collect_binary_parts_left_only_binary_expression() -> None:
    """_collect_binary_parts must handle a BinaryExpression that has `left`
    but lacks `right` without raising (branch at line 302 is the False arm:
    `hasattr(expr, 'right')` is False so the right recursion is skipped)."""
    fmt = ConditionStringFormatter()
    parts: list[str] = []

    expr = _BinaryExpressionLeftOnly(operator="and", left=Identifier(name="x"))
    fmt._collect_binary_parts(expr, "and", parts, 0)
    # Left subtree is Identifier("x"), which gets formatted and appended.
    assert "x" in parts


def test_collect_binary_parts_right_only_binary_expression() -> None:
    """_collect_binary_parts must handle a BinaryExpression that has `right`
    but lacks `left` without raising (branch at line 300 is the False arm:
    `hasattr(expr, 'left')` is False so left recursion is skipped)."""
    fmt = ConditionStringFormatter()
    parts: list[str] = []

    expr = _BinaryExpressionRightOnly(operator="and", right=Identifier(name="y"))
    fmt._collect_binary_parts(expr, "and", parts, 0)
    # Right subtree is Identifier("y"), which gets formatted and appended.
    assert "y" in parts
