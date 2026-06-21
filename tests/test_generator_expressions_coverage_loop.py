# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests targeting uncovered branches in yaraast/codegen/generator_expressions.py.

Each test exercises a real production code path — no mocks, no stubs.  All
assertions validate actual return values or exception messages produced by the
live implementation.
"""

from __future__ import annotations

import pytest

from yaraast.ast.conditions import ForOfExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    DoubleLiteral,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    SetExpression,
    StringIdentifier,
    StringLiteral,
    UnaryExpression,
)
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.generator_expressions import (
    _has_invalid_static_percentage_operand,
    _integer_remainder,
    _is_percentage_quantifier,
    _reject_restricted_of_rule_set_items,
    _render_quantifier,
    _render_rule_set_item,
    _render_rule_wildcard,
    _render_string_set,
    _render_string_set_item,
    _shift_left_int64,
    _shift_right_int64,
    _static_integer_quantifier_value,
    _validate_quantifier_text,
    reject_restricted_of_expression,
)

# ---------------------------------------------------------------------------
# _render_string_set: SetExpression with mixed rule + string items (lines 53-55)
# ---------------------------------------------------------------------------


def test_render_string_set_set_expression_mixed_items_raises() -> None:
    """SetExpression containing both a rule identifier and a string identifier raises."""
    gen = CodeGenerator()
    mixed = SetExpression(elements=[Identifier(name="rule_a"), StringIdentifier(name="$str1")])
    with pytest.raises(ValueError, match="Mixed string and rule set items"):
        _render_string_set(gen, mixed)


# ---------------------------------------------------------------------------
# _render_string_set: list branch - rule set items (lines 61-62)
# ---------------------------------------------------------------------------


def test_render_string_set_list_rule_set_items() -> None:
    """A list of rule-identifier nodes produces a parenthesised comma-joined string."""
    gen = CodeGenerator()
    items: list[Identifier] = [Identifier(name="rule_a"), Identifier(name="rule_b")]
    result = _render_string_set(gen, items)
    assert result == "(rule_a, rule_b)"


def test_render_string_set_tuple_rule_set_items() -> None:
    """A tuple of rule-identifier nodes produces a parenthesised comma-joined string."""
    gen = CodeGenerator()
    items = (Identifier(name="rule_c"),)
    result = _render_string_set(gen, items)
    assert result == "(rule_c)"


# ---------------------------------------------------------------------------
# _render_string_set: list branch - mixed items (lines 63-65)
# ---------------------------------------------------------------------------


def test_render_string_set_list_mixed_items_raises() -> None:
    """A list mixing rule identifiers and string identifiers raises ValueError."""
    gen = CodeGenerator()
    mixed: list[Identifier | StringIdentifier] = [
        Identifier(name="rule_a"),
        StringIdentifier(name="$str1"),
    ]
    with pytest.raises(ValueError, match="Mixed string and rule set items"):
        _render_string_set(gen, mixed)


def test_render_string_set_tuple_mixed_items_raises() -> None:
    """A tuple mixing rule identifiers and string identifiers raises ValueError."""
    gen = CodeGenerator()
    mixed = (Identifier(name="rule_b"), StringIdentifier(name="$str2"))
    with pytest.raises(ValueError, match="Mixed string and rule set items"):
        _render_string_set(gen, mixed)


# ---------------------------------------------------------------------------
# _render_string_set: set/frozenset branch - rule set items (lines 71-73)
# The branch is reached when sorted items satisfy _is_rule_set_items.
# AST nodes are unhashable, so this branch is only reachable via a subclass
# that IS hashable; there is currently no such path in production data.
# The mixed-items branch (lines 74-76) has the same constraint.
# These two branches are structurally unreachable with real AST nodes.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# _reject_restricted_of_rule_set_items: ParenthesesExpression (lines 119-120)
# ---------------------------------------------------------------------------


def test_reject_restricted_paren_wrapping_rule_identifier() -> None:
    """ParenthesesExpression wrapping a rule identifier triggers the restriction."""
    paren = ParenthesesExpression(expression=Identifier(name="rule_a"))
    with pytest.raises(ValueError, match="Rule sets cannot use at/in restrictions"):
        _reject_restricted_of_rule_set_items(paren)


# ---------------------------------------------------------------------------
# _reject_restricted_of_rule_set_items: SetExpression (lines 121-123)
# ---------------------------------------------------------------------------


def test_reject_restricted_set_expression_containing_rule_item() -> None:
    """SetExpression containing a rule identifier triggers the restriction."""
    set_expr = SetExpression(elements=[Identifier(name="rule_b")])
    with pytest.raises(ValueError, match="Rule sets cannot use at/in restrictions"):
        _reject_restricted_of_rule_set_items(set_expr)


# ---------------------------------------------------------------------------
# _reject_restricted_of_rule_set_items: list/tuple/set/frozenset (lines 124-126)
# ---------------------------------------------------------------------------


def test_reject_restricted_list_containing_rule_item() -> None:
    """A list containing a rule identifier triggers the restriction."""
    with pytest.raises(ValueError, match="Rule sets cannot use at/in restrictions"):
        _reject_restricted_of_rule_set_items([Identifier(name="rule_c")])


def test_reject_restricted_tuple_containing_rule_item() -> None:
    """A tuple containing a rule identifier triggers the restriction."""
    with pytest.raises(ValueError, match="Rule sets cannot use at/in restrictions"):
        _reject_restricted_of_rule_set_items((Identifier(name="rule_d"),))


# ---------------------------------------------------------------------------
# _is_percentage_quantifier: float literal (line 138)
# ---------------------------------------------------------------------------


def test_is_percentage_quantifier_raw_float() -> None:
    """A raw Python float is always a percentage quantifier."""
    assert _is_percentage_quantifier(3.14) is True
    assert _is_percentage_quantifier(0.5) is True


# ---------------------------------------------------------------------------
# _is_percentage_quantifier: UnaryExpression with '%' operator (line 149)
# ---------------------------------------------------------------------------


def test_is_percentage_quantifier_unary_percent_operator() -> None:
    """UnaryExpression with '%' operator is classified as a percentage quantifier."""
    uexpr = UnaryExpression(operator="%", operand=IntegerLiteral(value=50))
    assert _is_percentage_quantifier(uexpr) is True


# ---------------------------------------------------------------------------
# _is_percentage_quantifier: ParenthesesExpression (line 151)
# ---------------------------------------------------------------------------


def test_is_percentage_quantifier_parentheses_wrapping_double() -> None:
    """ParenthesesExpression wrapping a DoubleLiteral is a percentage quantifier."""
    paren = ParenthesesExpression(expression=DoubleLiteral(value=0.5))
    assert _is_percentage_quantifier(paren) is True


def test_is_percentage_quantifier_parentheses_non_percentage() -> None:
    """ParenthesesExpression wrapping a plain integer literal is not a percentage."""
    paren = ParenthesesExpression(expression=IntegerLiteral(value=3))
    assert _is_percentage_quantifier(paren) is False


# ---------------------------------------------------------------------------
# _render_rule_set_item: unsupported type raises (lines 205-206)
# ---------------------------------------------------------------------------


def test_render_rule_set_item_unsupported_type_raises() -> None:
    """Passing a node type that is neither Identifier nor StringWildcard raises."""
    with pytest.raises(ValueError, match="Unsupported rule set item"):
        _render_rule_set_item(StringLiteral(value="oops"))


# ---------------------------------------------------------------------------
# _render_rule_wildcard: invalid patterns (lines 221-222)
# ---------------------------------------------------------------------------


def test_render_rule_wildcard_starts_with_dollar_raises() -> None:
    """Wildcard pattern starting with '$' is invalid for rule sets."""
    with pytest.raises(ValueError, match="Invalid string or rule set wildcard"):
        _render_rule_wildcard("$rule*")


def test_render_rule_wildcard_no_trailing_star_raises() -> None:
    """Wildcard pattern without trailing '*' is invalid."""
    with pytest.raises(ValueError, match="Invalid string or rule set wildcard"):
        _render_rule_wildcard("rule")


def test_render_rule_wildcard_bare_star_raises() -> None:
    """Bare '*' is invalid as a rule wildcard."""
    with pytest.raises(ValueError, match="Invalid string or rule set wildcard"):
        _render_rule_wildcard("*")


# ---------------------------------------------------------------------------
# _render_string_set_item: Identifier with name not starting with '$' (line 250)
# The branch calls gen.visit(item) for module-path style identifiers.
# ---------------------------------------------------------------------------


def test_render_string_set_item_identifier_no_dollar_prefix() -> None:
    """Identifier whose name does not start with '$' is rendered via gen.visit."""
    gen = CodeGenerator()
    item = Identifier(name="my_module")
    result = _render_string_set_item(gen, item)
    assert result == "my_module"


# ---------------------------------------------------------------------------
# _render_quantifier: UnaryExpression '%' when allow_percentage=False (lines 334-335)
# ---------------------------------------------------------------------------


def test_render_quantifier_percent_unary_not_allowed_raises() -> None:
    """UnaryExpression with '%' operator raises when allow_percentage is False."""
    gen = CodeGenerator()
    uexpr = UnaryExpression(operator="%", operand=IntegerLiteral(value=50))
    with pytest.raises(ValueError, match="Invalid for quantifier"):
        _render_quantifier(gen, uexpr, allow_percentage=False, context="for quantifier")


# ---------------------------------------------------------------------------
# _validate_quantifier_text: non-string input (lines 365-366)
# ---------------------------------------------------------------------------


def test_validate_quantifier_text_non_string_raises() -> None:
    """Non-string input to _validate_quantifier_text raises ValueError."""
    with pytest.raises((ValueError, TypeError)):
        _validate_quantifier_text(42, allow_percentage=False)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _validate_quantifier_text: integer string returns formatted integer (line 375)
# ---------------------------------------------------------------------------


def test_validate_quantifier_text_integer_string() -> None:
    """A string representing a non-negative integer is accepted and formatted."""
    result = _validate_quantifier_text("5", allow_percentage=False)
    assert result == "5"

    result_zero = _validate_quantifier_text("0", allow_percentage=False)
    assert result_zero == "0"


# ---------------------------------------------------------------------------
# _validate_quantifier_text: percentage string (line 385)
# ---------------------------------------------------------------------------


def test_validate_quantifier_text_percentage_string_allowed() -> None:
    """A percentage string is accepted when allow_percentage is True."""
    result = _validate_quantifier_text("50%", allow_percentage=True)
    assert result == "50%"

    result_100 = _validate_quantifier_text("100%", allow_percentage=True)
    assert result_100 == "100%"


def test_validate_quantifier_text_percentage_string_not_allowed_raises() -> None:
    """A percentage string raises when allow_percentage is False."""
    with pytest.raises(ValueError, match="Invalid quantifier"):
        _validate_quantifier_text("50%", allow_percentage=False)


# ---------------------------------------------------------------------------
# _has_invalid_static_percentage_operand: StringLiteral (line 451)
# ---------------------------------------------------------------------------


def test_has_invalid_static_percentage_operand_string_literal() -> None:
    """StringLiteral is an invalid operand for a percentage expression quantifier."""
    result = _has_invalid_static_percentage_operand(StringLiteral(value="hello"))
    assert result is True


# ---------------------------------------------------------------------------
# _static_integer_quantifier_value: IntegerLiteral (line 472)
# ---------------------------------------------------------------------------


def test_static_integer_quantifier_value_integer_literal() -> None:
    """IntegerLiteral nodes return their integer value."""
    assert _static_integer_quantifier_value(IntegerLiteral(value=42)) == 42
    assert _static_integer_quantifier_value(IntegerLiteral(value=0)) == 0


# ---------------------------------------------------------------------------
# _static_integer_quantifier_value: UnaryExpression with None operand (line 484)
# ---------------------------------------------------------------------------


def test_static_integer_quantifier_value_unary_none_operand() -> None:
    """UnaryExpression whose operand resolves to None propagates None."""
    # Identifier resolves to None in _static_integer_quantifier_value
    uexpr = UnaryExpression(operator="-", operand=Identifier(name="count"))
    assert _static_integer_quantifier_value(uexpr) is None


# ---------------------------------------------------------------------------
# _static_integer_quantifier_value: UnaryExpression '~' operator (lines 487-489)
# ---------------------------------------------------------------------------


def test_static_integer_quantifier_value_unary_bitwise_not() -> None:
    """UnaryExpression with '~' returns bitwise NOT of the operand value."""
    uexpr = UnaryExpression(operator="~", operand=IntegerLiteral(value=5))
    result = _static_integer_quantifier_value(uexpr)
    assert result == ~5


def test_static_integer_quantifier_value_unary_negate() -> None:
    """UnaryExpression with '-' returns negated operand value."""
    uexpr = UnaryExpression(operator="-", operand=IntegerLiteral(value=7))
    result = _static_integer_quantifier_value(uexpr)
    assert result == -7


# ---------------------------------------------------------------------------
# _static_integer_quantifier_value: BinaryExpression branch for '<<' / '>>'
# with negative right operand returns None (line 503)
# ---------------------------------------------------------------------------


def test_static_integer_quantifier_value_shift_left_negative_right_returns_none() -> None:
    """Left-shift with a negative right operand returns None (undefined behaviour)."""
    expr = BinaryExpression(left=IntegerLiteral(4), operator="<<", right=IntegerLiteral(-1))
    assert _static_integer_quantifier_value(expr) is None


def test_static_integer_quantifier_value_shift_right_negative_right_returns_none() -> None:
    """Right-shift with a negative right operand returns None."""
    expr = BinaryExpression(left=IntegerLiteral(4), operator=">>", right=IntegerLiteral(-2))
    assert _static_integer_quantifier_value(expr) is None


# ---------------------------------------------------------------------------
# _static_integer_quantifier_value: BinaryExpression right >= 64 returns 0 (line 505)
# ---------------------------------------------------------------------------


def test_static_integer_quantifier_value_shift_left_right_gte_64_returns_zero() -> None:
    """Left-shift by 64 or more bits returns 0."""
    expr = BinaryExpression(left=IntegerLiteral(4), operator="<<", right=IntegerLiteral(64))
    assert _static_integer_quantifier_value(expr) == 0


def test_static_integer_quantifier_value_shift_right_right_gte_64_returns_zero() -> None:
    """Right-shift by 64 or more bits returns 0 (via _shift_right_int64)."""
    expr = BinaryExpression(left=IntegerLiteral(128), operator=">>", right=IntegerLiteral(64))
    assert _static_integer_quantifier_value(expr) == 0


# ---------------------------------------------------------------------------
# _static_integer_quantifier_value: '+' operator (line 512)
# ---------------------------------------------------------------------------


def test_static_integer_quantifier_value_addition() -> None:
    """BinaryExpression with '+' returns the sum normalised to int64."""
    expr = BinaryExpression(left=IntegerLiteral(3), operator="+", right=IntegerLiteral(4))
    assert _static_integer_quantifier_value(expr) == 7


# ---------------------------------------------------------------------------
# _static_integer_quantifier_value: '%' operator (line 517)
# Also covers the right == 0 guard (line 516-517 returns None for zero divisor).
# ---------------------------------------------------------------------------


def test_static_integer_quantifier_value_modulo_nonzero_divisor() -> None:
    """BinaryExpression with '%' returns the YARA-integer remainder."""
    expr = BinaryExpression(left=IntegerLiteral(10), operator="%", right=IntegerLiteral(3))
    assert _static_integer_quantifier_value(expr) == 1


def test_static_integer_quantifier_value_modulo_zero_divisor_returns_none() -> None:
    """BinaryExpression with '%' and right == 0 returns None (division by zero)."""
    expr = BinaryExpression(left=IntegerLiteral(10), operator="%", right=IntegerLiteral(0))
    assert _static_integer_quantifier_value(expr) is None


# ---------------------------------------------------------------------------
# _static_integer_quantifier_value: '<<' operator with valid right (line 521)
# ---------------------------------------------------------------------------


def test_static_integer_quantifier_value_shift_left_valid() -> None:
    """Left-shift with a non-negative right < 64 returns the shifted value."""
    expr = BinaryExpression(left=IntegerLiteral(2), operator="<<", right=IntegerLiteral(3))
    assert _static_integer_quantifier_value(expr) == 16


# ---------------------------------------------------------------------------
# _static_integer_quantifier_value: '>>' operator with valid right (line 525)
# ---------------------------------------------------------------------------


def test_static_integer_quantifier_value_shift_right_valid() -> None:
    """Right-shift with a non-negative right < 64 returns the shifted value."""
    expr = BinaryExpression(left=IntegerLiteral(16), operator=">>", right=IntegerLiteral(2))
    assert _static_integer_quantifier_value(expr) == 4


# ---------------------------------------------------------------------------
# _static_integer_quantifier_value: '&', '|', '^' operators (lines 527-532)
# ---------------------------------------------------------------------------


def test_static_integer_quantifier_value_bitwise_and() -> None:
    """BinaryExpression with '&' returns the bitwise AND normalised to int64."""
    expr = BinaryExpression(left=IntegerLiteral(6), operator="&", right=IntegerLiteral(3))
    assert _static_integer_quantifier_value(expr) == 2


def test_static_integer_quantifier_value_bitwise_or() -> None:
    """BinaryExpression with '|' returns the bitwise OR normalised to int64."""
    expr = BinaryExpression(left=IntegerLiteral(5), operator="|", right=IntegerLiteral(2))
    assert _static_integer_quantifier_value(expr) == 7


def test_static_integer_quantifier_value_bitwise_xor() -> None:
    """BinaryExpression with '^' returns the bitwise XOR normalised to int64."""
    expr = BinaryExpression(left=IntegerLiteral(6), operator="^", right=IntegerLiteral(4))
    assert _static_integer_quantifier_value(expr) == 2


# ---------------------------------------------------------------------------
# _integer_remainder: same-sign operands - branch 544->546 (condition is False)
# ---------------------------------------------------------------------------


def test_integer_remainder_both_positive() -> None:
    """Both operands positive: the sign adjustment is skipped."""
    assert _integer_remainder(10, 3) == 1


def test_integer_remainder_both_negative() -> None:
    """Both operands negative: the sign adjustment is skipped."""
    assert _integer_remainder(-10, -3) == -1


def test_integer_remainder_mixed_signs() -> None:
    """Mixed-sign operands: the quotient sign is negated (line 545 is taken)."""
    assert _integer_remainder(-10, 3) == -1
    assert _integer_remainder(10, -3) == 1


# ---------------------------------------------------------------------------
# _shift_left_int64: right >= 64 returns 0 (line 563)
# ---------------------------------------------------------------------------


def test_shift_left_int64_right_gte_64_returns_zero() -> None:
    """Shifting left by 64 or more bits always yields 0."""
    assert _shift_left_int64(1, 64) == 0
    assert _shift_left_int64(100, 65) == 0


def test_shift_left_int64_right_lt_64_normalises() -> None:
    """Shifting left by less than 64 bits normalises to int64 range."""
    assert _shift_left_int64(1, 3) == 8


# ---------------------------------------------------------------------------
# _shift_right_int64: right >= 64 returns 0 (line 569)
# ---------------------------------------------------------------------------


def test_shift_right_int64_right_gte_64_returns_zero() -> None:
    """Shifting right by 64 or more bits always yields 0."""
    assert _shift_right_int64(100, 64) == 0
    assert _shift_right_int64(1, 70) == 0


def test_shift_right_int64_right_lt_64_returns_shifted() -> None:
    """Shifting right by less than 64 bits returns the shifted value."""
    assert _shift_right_int64(64, 2) == 16


# ---------------------------------------------------------------------------
# Integration: end-to-end rendering through CodeGenerator for key paths
# ---------------------------------------------------------------------------


def test_render_of_expression_with_list_string_set() -> None:
    """OfExpression with a list-based string set renders correctly."""
    gen = CodeGenerator()
    node = OfExpression(
        quantifier="any",
        string_set=[StringIdentifier(name="$a"), StringIdentifier(name="$b")],
    )
    result = gen.visit(node)
    assert result == "any of ($a, $b)"


def test_render_of_expression_with_rule_identifier_list() -> None:
    """OfExpression with a list of rule identifiers renders correctly."""
    gen = CodeGenerator()
    node = OfExpression(
        quantifier="all",
        string_set=[Identifier(name="rule_one"), Identifier(name="rule_two")],
    )
    result = gen.visit(node)
    assert result == "all of (rule_one, rule_two)"


def test_render_for_of_expression_with_rule_set_string_set() -> None:
    """ForOfExpression with list string_set and no condition renders as quantifier of set."""
    gen = CodeGenerator()
    node = ForOfExpression(
        quantifier="any",
        string_set=[StringIdentifier(name="$a")],
        condition=None,
    )
    result = gen.visit(node)
    assert result == "any of ($a)"


def test_render_quantifier_percent_unary_with_binary_operand() -> None:
    """UnaryExpression '%' with BinaryExpression operand wraps operand in parens."""
    gen = CodeGenerator()
    bin_expr = BinaryExpression(left=IntegerLiteral(3), operator="+", right=IntegerLiteral(2))
    uexpr = UnaryExpression(operator="%", operand=bin_expr)
    node = OfExpression(quantifier=uexpr, string_set=Identifier(name="them"))
    result = gen.visit(node)
    assert result == "(3 + 2)% of them"


def test_reject_restricted_of_expression_with_percentage_quantifier_raises() -> None:
    """reject_restricted_of_expression raises when OfExpression uses a percentage quantifier
    and has at/in restrictions (is_percentage_quantifier)."""
    # Build an OfExpression and call reject_restricted_of_expression directly
    node = OfExpression(quantifier=DoubleLiteral(value=0.5), string_set=Identifier(name="them"))
    with pytest.raises(ValueError, match="Percentage of-expressions do not support"):
        reject_restricted_of_expression(node)
