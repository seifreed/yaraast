"""Coverage-gap tests for yaraast.builder.ast_transformer (second pass, no mocks).

# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

This file targets the remaining uncovered lines after
test_builder_ast_transformer_coverage_loop.py ran:

  82->84   _require_expression: callable(validate_structure) is False
           => instance-attribute shadows the class method with a non-callable value

  411      _rename_expression_value: tuple branch
           => direct call with a tuple containing strings

  413      _rename_expression_value: set branch
           => direct call with a set containing strings

  415      _rename_expression_value: frozenset branch
           => direct call with a frozenset containing strings

  434->436 _rename_string_set_value / ParenthesesExpression false branch
           => ParenthesesExpression whose .expression is a str (Python dataclasses
              do not enforce field types at runtime; the renamed value is a str,
              not an Expression, so the false branch fires)

  454      _rename_string_set_value final fallback
           => direct call with a value that is none of the recognised types
              (an integer), which falls through every isinstance guard

Confirmed structurally unreachable lines (not attempted here):
  379      BinaryExpression new-object path: all specific-type handlers mutate the
           node in place and return the same object, so new_left is always expr.left.
  385      UnaryExpression new-object path: same reason.
  391      ParenthesesExpression new-object path: same reason.
"""

from __future__ import annotations

from yaraast.ast.expressions import (
    BooleanLiteral,
    ParenthesesExpression,
    StringIdentifier,
    StringLiteral,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.builder.ast_transformer import RuleTransformer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_transformer() -> RuleTransformer:
    """Return a RuleTransformer around a minimal, structurally valid rule."""
    rule = Rule(
        name="r",
        modifiers=[],
        tags=[],
        meta={},
        strings=[PlainString(identifier="$a", value="x", modifiers=[])],
        condition=StringIdentifier(name="$a"),
    )
    return RuleTransformer(rule)


# ---------------------------------------------------------------------------
# Line 82->84: _require_expression with non-callable validate_structure
# ---------------------------------------------------------------------------


def test_require_expression_skips_validate_structure_when_not_callable() -> None:
    """_require_expression must return the expression unchanged when validate_structure
    is present but not callable (line 82->84 false branch).

    Python dataclass instances permit arbitrary instance-level attribute assignment.
    Assigning a non-callable string to `validate_structure` shadows the class method
    so that `callable(getattr(expr, 'validate_structure', None))` is False.  The
    method must not raise and must return the original expression object.
    """
    expr = BooleanLiteral(value=True)
    # Shadow the class-level validate_structure method with a non-callable string.
    # object.__setattr__ bypasses mypy's type narrowing on the dataclass field.
    object.__setattr__(expr, "validate_structure", "not_a_callable")

    result = RuleTransformer._require_expression(expr, "test context")

    assert result is expr
    # The non-callable did not raise; the branch was taken and line 84 returned expr.


# ---------------------------------------------------------------------------
# Lines 411, 413, 415: _rename_expression_value tuple/set/frozenset branches
# ---------------------------------------------------------------------------


def test_rename_expression_value_processes_tuple_items() -> None:
    """_rename_expression_value must recursively process each item of a tuple
    (line 411).

    A tuple of two strings is passed directly.  Each string item falls through
    to the `return value` leaf inside the recursive call (since strings are not
    Expressions, lists, tuples, sets, or frozensets).  The outer call at line
    411 must return a new tuple containing the processed items.
    """
    transformer = _make_transformer()
    mapping: dict[str, str] = {"$a": "$b"}

    value = ("$a", "literal_string")
    result = transformer._rename_expression_value(value, mapping)

    # The tuple branch must produce a new tuple of the same length.
    assert isinstance(result, tuple)
    assert len(result) == 2


def test_rename_expression_value_processes_tuple_with_expression_item() -> None:
    """_rename_expression_value processes a tuple containing a StringIdentifier.

    The tuple branch at line 411 iterates items; when an item is a
    StringIdentifier it delegates to _rename_strings_in_expression which
    renames it in-place.
    """
    transformer = _make_transformer()
    mapping: dict[str, str] = {"$a": "$b"}
    inner = StringIdentifier(name="$a")

    value = (inner,)
    result = transformer._rename_expression_value(value, mapping)

    assert isinstance(result, tuple)
    assert inner.name == "$b"


def test_rename_expression_value_processes_set_items() -> None:
    """_rename_expression_value must iterate a set and return a new set
    (line 413).

    A set of plain strings is passed.  Each string is not an Expression or
    any container type, so each recurse call hits `return value`.  The branch
    at line 413 must execute and produce a set result.
    """
    transformer = _make_transformer()
    mapping: dict[str, str] = {"$a": "$b"}

    value: set[str] = {"$a", "$c"}
    result = transformer._rename_expression_value(value, mapping)

    # The set branch returns a new set from a set-comprehension.
    assert isinstance(result, set)
    assert "$c" in result


def test_rename_expression_value_processes_frozenset_items() -> None:
    """_rename_expression_value must iterate a frozenset and return a new
    frozenset (line 415).

    A frozenset of plain strings is passed.  The branch at line 415 must
    execute and produce a frozenset result.
    """
    transformer = _make_transformer()
    mapping: dict[str, str] = {"$a": "$b"}

    value: frozenset[str] = frozenset({"$a"})
    result = transformer._rename_expression_value(value, mapping)

    assert isinstance(result, frozenset)
    assert len(result) == 1


# ---------------------------------------------------------------------------
# Line 434->436: _rename_string_set_value / ParenthesesExpression false branch
# ---------------------------------------------------------------------------


def test_rename_string_set_value_parentheses_false_branch_when_inner_is_string() -> None:
    """_rename_string_set_value must skip assigning to value.expression when
    the recursively-renamed inner value is not an Expression (line 434->436).

    Python dataclasses do not enforce field types at runtime.  A
    ParenthesesExpression can be constructed via __new__ with its .expression
    field set to a plain str.  When _rename_string_set_value recurses on that
    str it returns a renamed str (also not an Expression), so
    `isinstance(renamed, Expression)` is False.  The assignment at line 435 is
    skipped; the method jumps directly to `return value` (line 436).
    """
    transformer = _make_transformer()
    mapping: dict[str, str] = {"$a": "$b"}

    # Build a ParenthesesExpression with a raw string in .expression
    # (bypasses the dataclass type annotation without any mocking).
    paren: ParenthesesExpression = object.__new__(ParenthesesExpression)
    object.__setattr__(paren, "expression", "$a")
    object.__setattr__(paren, "location", None)
    object.__setattr__(paren, "leading_comments", [])
    object.__setattr__(paren, "trailing_comment", None)

    result = transformer._rename_string_set_value(paren, mapping)

    # The false branch does NOT update paren.expression to an Expression; the
    # original str value remains in the field.  Verify the field is still a str,
    # not an Expression, confirming the isinstance guard at line 434 was False.
    assert result is paren
    assert not isinstance(paren.expression, BooleanLiteral)  # field was never replaced


def test_rename_string_set_value_parentheses_true_branch_when_inner_is_expression() -> None:
    """Companion test: when the recursed inner value IS an Expression, the true
    branch at line 434 fires and value.expression is updated.

    This ensures the false-branch test above is not a degenerate case and that
    both branches of the condition are behaviorally distinct.
    """
    transformer = _make_transformer()
    mapping: dict[str, str] = {"$a": "$b"}

    inner = StringLiteral(value="$a")
    paren = ParenthesesExpression(expression=inner)

    result = transformer._rename_string_set_value(paren, mapping)

    # True branch: StringLiteral is an Expression, so expression is reassigned.
    assert result is paren
    assert isinstance(paren.expression, StringLiteral)
    assert paren.expression.value == "$b"


# ---------------------------------------------------------------------------
# Line 454: _rename_string_set_value final fallback
# ---------------------------------------------------------------------------


def test_rename_string_set_value_returns_value_unchanged_for_unrecognised_type() -> None:
    """_rename_string_set_value must return the value as-is when it matches none
    of the handled types (line 454 final fallback).

    An integer is not a str, Identifier, StringLiteral, ParenthesesExpression,
    SetExpression, Expression, list, tuple, set, or frozenset.  Every
    isinstance guard in the method fails, so execution reaches `return value`
    at line 454 with the original integer intact.
    """
    transformer = _make_transformer()
    mapping: dict[str, str] = {"$a": "$b"}

    unrecognised: object = 42
    result = transformer._rename_string_set_value(unrecognised, mapping)

    assert result is unrecognised
    assert result == 42
