# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests targeting the remaining uncovered branches in
yaraast/codegen/generator_expressions.py after
tests/test_generator_expressions_coverage_loop.py reached 97.10%.

Items targeted by this file (all verified reachable with real inputs):

  Lines 72-73   _render_string_set: set/frozenset branch, all-rule-set items path.
  Lines 75-76   _render_string_set: set/frozenset branch, mixed rule+string items path.
  Line  120     _reject_restricted_of_rule_set_items: ParenthesesExpression non-raising return.
  Line  123     _reject_restricted_of_rule_set_items: SetExpression non-raising return.
  Line  125->exit  same function: list/tuple branch loop exits normally.
  Line  472     _static_integer_quantifier_value: raw Python int input.
  Lines 487->489   same function: UnaryExpression with operand resolving to non-None
                  but operator is neither '-' nor '~' (falls through to BinaryExpression
                  check returning None).
  Line  512     same function: BinaryExpression '-' operator result path.

Items confirmed as structurally dead code (not tested here):

  Lines 520-521   Right < 0 guard for '<<' at line 520 is unreachable because the outer
                  guard at line 501-503 already returns None for any shift with right < 0
                  before left is evaluated.
  Lines 524-525   Same reasoning for '>>'.
All tests follow the AAA pattern (Arrange / Act / Assert) and call the
production functions directly with concrete AST nodes.  No mocks, stubs,
or placeholder implementations are used.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from yaraast.ast.expressions import (
    BinaryExpression,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    SetExpression,
    StringIdentifier,
    StringWildcard,
    UnaryExpression,
)
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.generator_expressions import (
    _reject_restricted_of_rule_set_items,
    _render_string_set,
    _static_integer_quantifier_value,
)

# ---------------------------------------------------------------------------
# Helpers: hashable AST node subclasses
#
# The set/frozenset branch of _render_string_set requires hashable items to
# build a Python set.  The production AST dataclasses are non-frozen and
# therefore unhashable by default.  Using dataclass(unsafe_hash=True) on
# subclasses gives them an identity-based __hash__ while keeping all
# production isinstance() checks intact — no production logic is altered.
# ---------------------------------------------------------------------------


@dataclass(unsafe_hash=True)
class _HashableIdentifier(Identifier):
    """Identifier subclass that is hashable, for use in Python sets."""


@dataclass(unsafe_hash=True)
class _HashableStringIdentifier(StringIdentifier):
    """StringIdentifier subclass that is hashable, for use in Python sets."""


@dataclass(unsafe_hash=True)
class _HashableStringWildcard(StringWildcard):
    """StringWildcard subclass that is hashable, for use in Python sets."""


# ---------------------------------------------------------------------------
# _render_string_set: set branch — all rule-set items (lines 72-73)
# ---------------------------------------------------------------------------


def test_render_string_set_set_of_rule_identifiers() -> None:
    """A Python set of rule-identifier nodes is rendered as a parenthesised,
    comma-joined list sorted by string representation.

    This exercises lines 71-73: the set branch that calls _is_rule_set_items
    (returns True) and then renders each item via _render_rule_set_item.
    """
    gen = CodeGenerator()
    # Arrange: a set with two hashable rule-identifier nodes
    rule_set = {
        _HashableIdentifier(name="rule_alpha"),
        _HashableIdentifier(name="rule_beta"),
    }

    # Act
    result = _render_string_set(gen, rule_set)

    # Assert: sorted(key=str) → alphabetical order
    assert result in {"(rule_alpha, rule_beta)", "(rule_beta, rule_alpha)"}
    assert result.startswith("(")
    assert result.endswith(")")
    assert "rule_alpha" in result
    assert "rule_beta" in result


def test_render_string_set_frozenset_of_rule_wildcards() -> None:
    """A Python frozenset of rule-wildcard nodes is rendered correctly.

    This also exercises the set/frozenset branch (lines 71-73) via frozenset
    with StringWildcard items that are rule wildcards (non-'$' prefix).
    """
    gen = CodeGenerator()
    # Arrange: frozenset with a single hashable rule-wildcard node
    rule_wildcard = _HashableStringWildcard(pattern="rule_a_*")
    rule_frozenset = frozenset([rule_wildcard])

    # Act
    result = _render_string_set(gen, rule_frozenset)

    # Assert
    assert result == "(rule_a_*)"


# ---------------------------------------------------------------------------
# _render_string_set: set branch — mixed rule + string items (lines 75-76)
# ---------------------------------------------------------------------------


def test_render_string_set_set_mixed_rule_and_string_items_raises() -> None:
    """A Python set containing both a rule identifier and a string identifier
    raises ValueError with the canonical mixed-items message.

    This exercises lines 74-76: _has_mixed_rule_and_string_set_items returns
    True, triggering the error path in the set/frozenset branch.
    """
    gen = CodeGenerator()
    # Arrange: set of one rule item and one string item
    mixed = {
        _HashableIdentifier(name="rule_x"),
        _HashableStringIdentifier(name="$str1"),
    }

    # Act / Assert
    with pytest.raises(ValueError, match="Mixed string and rule set items"):
        _render_string_set(gen, mixed)


def test_render_string_set_frozenset_mixed_rule_and_string_items_raises() -> None:
    """A frozenset containing mixed rule + string items raises ValueError.

    Confirms the same mixed-items guard in the set/frozenset branch also fires
    for frozenset inputs.
    """
    gen = CodeGenerator()
    # Arrange
    mixed = frozenset(
        [
            _HashableIdentifier(name="rule_y"),
            _HashableStringIdentifier(name="$str2"),
        ]
    )

    # Act / Assert
    with pytest.raises(ValueError, match="Mixed string and rule set items"):
        _render_string_set(gen, mixed)


# ---------------------------------------------------------------------------
# _reject_restricted_of_rule_set_items: ParenthesesExpression non-raising
# return (line 120)
# ---------------------------------------------------------------------------


def test_reject_restricted_paren_wrapping_non_rule_returns_silently() -> None:
    """_reject_restricted_of_rule_set_items is silent when a
    ParenthesesExpression wraps a non-rule string identifier.

    This exercises the True branch of the ParenthesesExpression check at line
    118, makes the recursive call at line 119, and executes the ``return``
    statement at line 120 when no error is raised by the recursive call.
    """
    # Arrange: ParenthesesExpression wrapping a string identifier (not a rule item)
    paren = ParenthesesExpression(expression=StringIdentifier(name="$clean"))

    # Act (should not raise)
    _reject_restricted_of_rule_set_items(paren)

    # Assert: implicit — no exception means line 120's return executed


def test_reject_restricted_paren_double_nested_non_rule_returns_silently() -> None:
    """Double-nested ParenthesesExpression over a non-rule item is also silent.

    Each level of nesting exercises line 120's return in a separate recursive
    frame, providing additional path coverage for line 120.
    """
    # Arrange: two levels of parentheses around a string identifier
    inner = ParenthesesExpression(expression=StringIdentifier(name="$inner"))
    outer = ParenthesesExpression(expression=inner)

    # Act (should not raise)
    _reject_restricted_of_rule_set_items(outer)


# ---------------------------------------------------------------------------
# _reject_restricted_of_rule_set_items: SetExpression non-raising return
# (line 123)
# ---------------------------------------------------------------------------


def test_reject_restricted_set_expression_non_rule_returns_silently() -> None:
    """_reject_restricted_of_rule_set_items is silent when a SetExpression
    contains only non-rule string identifiers.

    This exercises the True branch of the SetExpression check at line 121,
    makes the recursive call at line 122 (passing the elements list), and
    executes the ``return`` statement at line 123.
    """
    # Arrange: SetExpression with only string-identifier elements
    set_expr = SetExpression(elements=[StringIdentifier(name="$s1"), StringIdentifier(name="$s2")])

    # Act (should not raise)
    _reject_restricted_of_rule_set_items(set_expr)

    # Assert: implicit


def test_reject_restricted_set_expression_them_returns_silently() -> None:
    """SetExpression with the 'them' keyword (Identifier) is also silent.

    'them' is a string-set keyword, not a rule identifier, so no error is
    raised.  Exercises line 123's return via the SetExpression branch.
    """
    # Arrange: SetExpression with Identifier('them')
    set_expr = SetExpression(elements=[Identifier(name="them")])

    # Act (should not raise)
    _reject_restricted_of_rule_set_items(set_expr)


# ---------------------------------------------------------------------------
# _reject_restricted_of_rule_set_items: list branch loop exits normally
# (line 125->exit)
# ---------------------------------------------------------------------------


def test_reject_restricted_list_of_non_rule_items_exits_normally() -> None:
    """A list of non-rule string identifiers completes the for loop and
    returns from the function without raising.

    This exercises the list|tuple|set|frozenset branch at line 124 and the
    loop body at line 125.  The coverage branch 125->exit corresponds to the
    for loop exiting after processing all items without raising.
    """
    # Arrange: list containing two string-identifier nodes (neither is a rule item)
    items = [StringIdentifier(name="$a"), StringIdentifier(name="$b"), StringIdentifier(name="$c")]

    # Act (should not raise)
    _reject_restricted_of_rule_set_items(items)

    # Assert: implicit


def test_reject_restricted_tuple_of_non_rule_items_exits_normally() -> None:
    """A tuple of non-rule string identifiers also exercises the loop-exit branch."""
    # Arrange
    items = (StringIdentifier(name="$x"), StringIdentifier(name="$y"))

    # Act (should not raise)
    _reject_restricted_of_rule_set_items(items)


# ---------------------------------------------------------------------------
# _static_integer_quantifier_value: raw Python int input (line 472)
# ---------------------------------------------------------------------------


def test_static_integer_quantifier_value_raw_int_positive() -> None:
    """A raw Python int returns the same value directly (line 472).

    The production code path at lines 471-472 handles raw ints that are not
    booleans.  The existing tests in loop.py only pass IntegerLiteral nodes;
    this test covers the raw-int branch.
    """
    # Arrange / Act
    result = _static_integer_quantifier_value(7)

    # Assert
    assert result == 7


def test_static_integer_quantifier_value_raw_int_zero() -> None:
    """A raw int of zero is returned as-is (line 472)."""
    assert _static_integer_quantifier_value(0) == 0


def test_static_integer_quantifier_value_raw_int_negative() -> None:
    """A negative raw int is returned as-is (line 472); callers validate range."""
    assert _static_integer_quantifier_value(-3) == -3


def test_static_integer_quantifier_value_raw_bool_returns_none() -> None:
    """A Python bool (subclass of int) is excluded from the raw-int branch and
    returns None because no other branch matches it.

    This validates the ``not isinstance(value, bool)`` guard at line 471.
    """
    assert _static_integer_quantifier_value(True) is None
    assert _static_integer_quantifier_value(False) is None


# ---------------------------------------------------------------------------
# _static_integer_quantifier_value: UnaryExpression with operator not '-'
# or '~' and a resolvable operand (lines 487->489)
# ---------------------------------------------------------------------------


def test_static_integer_quantifier_value_unary_unknown_operator_returns_none() -> None:
    """UnaryExpression with an operator other than '-' or '~' but whose
    operand resolves to a non-None integer falls through both operator checks
    at lines 485 and 487, reaching line 489 and ultimately returning None.

    The branch 487->489 in the coverage report is the False branch of
    ``if value.operator == '~':``: the condition is not taken, execution
    falls to line 489 (the BinaryExpression isinstance check).  Since the
    value is still a UnaryExpression, that check fails, and the function
    returns None at line 533.
    """
    # Arrange: operator 'not' is neither '-' nor '~'; operand resolves to 3
    uexpr = UnaryExpression(operator="not", operand=IntegerLiteral(value=3))

    # Act
    result = _static_integer_quantifier_value(uexpr)

    # Assert: no branch handles 'not', so None is returned
    assert result is None


def test_static_integer_quantifier_value_unary_bang_operator_returns_none() -> None:
    """UnaryExpression with '!' operator also falls through lines 485 and 487,
    covering the 487->489 branch."""
    # Arrange
    uexpr = UnaryExpression(operator="!", operand=IntegerLiteral(value=10))

    # Act
    result = _static_integer_quantifier_value(uexpr)

    # Assert
    assert result is None


# ---------------------------------------------------------------------------
# _static_integer_quantifier_value: BinaryExpression '-' subtraction (line 512)
# ---------------------------------------------------------------------------


def test_static_integer_quantifier_value_subtraction_positive_result() -> None:
    """BinaryExpression with '-' operator returns the int64-normalised
    difference of the two operands (line 512).

    The existing loop.py tests cover '+', '*', '%', '<<', '>>', '&', '|', '^'
    but not '-', leaving line 512 uncovered.
    """
    # Arrange
    expr = BinaryExpression(
        left=IntegerLiteral(value=10),
        operator="-",
        right=IntegerLiteral(value=3),
    )

    # Act
    result = _static_integer_quantifier_value(expr)

    # Assert
    assert result == 7


def test_static_integer_quantifier_value_subtraction_zero_result() -> None:
    """Subtraction producing zero is normalised to 0 (line 512)."""
    expr = BinaryExpression(
        left=IntegerLiteral(value=5),
        operator="-",
        right=IntegerLiteral(value=5),
    )
    assert _static_integer_quantifier_value(expr) == 0


def test_static_integer_quantifier_value_subtraction_negative_result() -> None:
    """Subtraction producing a value below zero is normalised via int64 wrap
    (line 512 calls _normalize_int64)."""
    # Arrange: 1 - 2 = -1, which wraps to the int64 representation
    expr = BinaryExpression(
        left=IntegerLiteral(value=1),
        operator="-",
        right=IntegerLiteral(value=2),
    )

    # Act
    result = _static_integer_quantifier_value(expr)

    # Assert: _normalize_int64(-1) = -1 (fits in int64 range)
    assert result == -1


def test_static_integer_quantifier_value_subtraction_right_operand_unresolvable() -> None:
    """Subtraction where the right operand is unresolvable returns None
    (line 507 short-circuits before reaching line 512)."""
    # Arrange: right operand is an Identifier — resolves to None
    expr = BinaryExpression(
        left=IntegerLiteral(value=10),
        operator="-",
        right=Identifier(name="count"),
    )

    # Act
    result = _static_integer_quantifier_value(expr)

    # Assert: None because right resolves to None
    assert result is None
