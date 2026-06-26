# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered lines in condition_builder.py.

Each test exercises real builder API paths. No mocks, no stubs, no
suppression comments. Coverage target: 100% of condition_builder.py.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.conditions import ForExpression, OfExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    Expression,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    RangeExpression,
    StringIdentifier,
    StringLiteral,
    UnaryExpression,
)
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.errors import ValidationError

# ---------------------------------------------------------------------------
# Module-level helper: _identifier_path_expression  (line 40)
# ---------------------------------------------------------------------------


def test_identifier_dotted_path_produces_nested_member_access() -> None:
    """_identifier_path_expression must chain MemberAccess for each dot segment."""
    # Arrange: a two-segment dotted path
    # Act
    result = ConditionBuilder().identifier("pe.sections").build()
    # Assert: outermost node is MemberAccess; inner object is the root Identifier
    assert isinstance(result, MemberAccess)
    assert result.member == "sections"
    assert isinstance(result.object, Identifier)
    assert result.object.name == "pe"


def test_identifier_three_segment_path_nests_correctly() -> None:
    """A three-part dotted identifier must produce two chained MemberAccess nodes."""
    result = ConditionBuilder().identifier("pe.sections.name").build()
    assert isinstance(result, MemberAccess)
    assert result.member == "name"
    assert isinstance(result.object, MemberAccess)
    assert result.object.member == "sections"


# ---------------------------------------------------------------------------
# false() literal  (line 99)
# ---------------------------------------------------------------------------


def test_false_returns_boolean_literal_with_false_value() -> None:
    """false() must return a BooleanLiteral(value=False)."""
    result = ConditionBuilder().false().build()
    assert isinstance(result, BooleanLiteral)
    assert result.value is False


# ---------------------------------------------------------------------------
# entrypoint() keyword  (line 111)
# ---------------------------------------------------------------------------


def test_entrypoint_returns_identifier_named_entrypoint() -> None:
    """entrypoint() must return Identifier(name='entrypoint')."""
    result = ConditionBuilder().entrypoint().build()
    assert isinstance(result, Identifier)
    assert result.name == "entrypoint"


# ---------------------------------------------------------------------------
# member_access() with a raw Expression object  (lines 126-127)
# ---------------------------------------------------------------------------


def test_member_access_accepts_raw_expression_as_object() -> None:
    """member_access() must accept a bare Expression as its obj argument."""
    # Arrange: pass a raw Identifier (an Expression subclass) directly
    raw: Expression = Identifier(name="pe")
    # Act
    result = ConditionBuilder().member_access(raw, "number_of_sections").build()
    # Assert
    assert isinstance(result, MemberAccess)
    assert result.member == "number_of_sections"
    assert isinstance(result.object, Identifier)
    assert result.object.name == "pe"


def test_member_access_accepts_condition_builder_as_object() -> None:
    """member_access() must also accept a ConditionBuilder as its obj argument."""
    obj = ConditionBuilder().identifier("pe")
    result = ConditionBuilder().member_access(obj, "version").build()
    assert isinstance(result, MemberAccess)
    assert result.member == "version"


# ---------------------------------------------------------------------------
# array_access() return  (line 137)
# ---------------------------------------------------------------------------


def test_array_access_returns_array_access_node() -> None:
    """array_access() must produce an ArrayAccess wrapping its arguments."""
    arr = ConditionBuilder().identifier("pe.sections")
    result = ConditionBuilder().array_access(arr, 0).build()
    assert isinstance(result, ArrayAccess)
    assert isinstance(result.index, IntegerLiteral)
    assert result.index.value == 0


def test_array_access_accepts_expression_index() -> None:
    """array_access() must accept a raw Expression as the index.

    build() deep-copies the tree, so structural equality is checked, not identity.
    """
    arr = ConditionBuilder().identifier("arr")
    idx: Expression = IntegerLiteral(value=3)
    result = ConditionBuilder().array_access(arr, idx).build()
    assert isinstance(result, ArrayAccess)
    assert isinstance(result.index, IntegerLiteral)
    assert result.index.value == 3


# ---------------------------------------------------------------------------
# or_() guard on empty builder  (lines 154-155)
# ---------------------------------------------------------------------------


def test_or_on_empty_builder_raises_validation_error() -> None:
    """or_() must raise ValidationError when called on an empty builder."""
    with pytest.raises(ValidationError, match="Cannot apply OR to empty expression"):
        ConditionBuilder().or_(ConditionBuilder().true())


# ---------------------------------------------------------------------------
# not_() guard on empty builder  (lines 165-166)
# ---------------------------------------------------------------------------


def test_not_on_empty_builder_raises_validation_error() -> None:
    """not_() must raise ValidationError when called on an empty builder."""
    with pytest.raises(ValidationError, match="Cannot apply NOT to empty expression"):
        ConditionBuilder().not_()


# ---------------------------------------------------------------------------
# ne()  (line 179)
# ---------------------------------------------------------------------------


def test_ne_produces_binary_expression_with_ne_operator() -> None:
    """ne() must return a BinaryExpression with operator '!='."""
    result = ConditionBuilder().integer(5).ne(3).build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "!="
    assert isinstance(result.left, IntegerLiteral)
    assert isinstance(result.right, IntegerLiteral)


# ---------------------------------------------------------------------------
# le()  (line 187)
# ---------------------------------------------------------------------------


def test_le_produces_binary_expression_with_le_operator() -> None:
    """le() must return a BinaryExpression with operator '<='."""
    result = ConditionBuilder().integer(5).le(10).build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "<="


# ---------------------------------------------------------------------------
# ge()  (line 195)
# ---------------------------------------------------------------------------


def test_ge_produces_binary_expression_with_ge_operator() -> None:
    """ge() must return a BinaryExpression with operator '>='."""
    result = ConditionBuilder().integer(5).ge(3).build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == ">="


# ---------------------------------------------------------------------------
# startswith / endswith / icontains / iequals  (lines 208, 212, 216, 220)
# ---------------------------------------------------------------------------


def test_startswith_produces_correct_binary_expression() -> None:
    """startswith() must produce a BinaryExpression with operator 'startswith'."""
    result = ConditionBuilder().identifier("filename").startswith("evil").build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "startswith"
    assert isinstance(result.right, StringLiteral)
    assert result.right.value == "evil"


def test_endswith_produces_correct_binary_expression() -> None:
    """endswith() must produce a BinaryExpression with operator 'endswith'."""
    result = ConditionBuilder().identifier("filename").endswith(".exe").build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "endswith"


def test_icontains_produces_correct_binary_expression() -> None:
    """icontains() must produce a BinaryExpression with operator 'icontains'."""
    result = ConditionBuilder().identifier("filename").icontains("virus").build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "icontains"


def test_iequals_produces_correct_binary_expression() -> None:
    """iequals() must produce a BinaryExpression with operator 'iequals'."""
    result = ConditionBuilder().identifier("filename").iequals("malware.exe").build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "iequals"


# ---------------------------------------------------------------------------
# at() guard: None expression and non-StringIdentifier  (lines 226-227)
# ---------------------------------------------------------------------------


def test_at_on_empty_builder_raises_validation_error() -> None:
    """at() must raise ValidationError when called on an empty builder."""
    with pytest.raises(ValidationError, match="'at' can only be used with string identifiers"):
        ConditionBuilder().at(0)


def test_at_on_non_string_identifier_raises_validation_error() -> None:
    """at() must raise ValidationError when the held expression is not a StringIdentifier."""
    with pytest.raises(ValidationError, match="'at' can only be used with string identifiers"):
        ConditionBuilder().integer(42).at(0)


# ---------------------------------------------------------------------------
# in_range() guard: None expression and non-StringIdentifier  (lines 241-242)
# ---------------------------------------------------------------------------


def test_in_range_on_empty_builder_raises_validation_error() -> None:
    """in_range() must raise ValidationError when called on an empty builder."""
    with pytest.raises(ValidationError, match="'in' can only be used with string identifiers"):
        ConditionBuilder().in_range(0, 10)


def test_in_range_on_non_string_identifier_raises_validation_error() -> None:
    """in_range() must raise ValidationError when the held expression is not a StringIdentifier."""
    with pytest.raises(ValidationError, match="'in' can only be used with string identifiers"):
        ConditionBuilder().integer(5).in_range(0, 10)


# ---------------------------------------------------------------------------
# n_of() with "them"  (line 286)
# ---------------------------------------------------------------------------


def test_n_of_with_them_uses_identifier_node() -> None:
    """n_of('them') must use Identifier(name='them') rather than a SetExpression."""
    result = ConditionBuilder().n_of(1, "them").build()
    assert isinstance(result, OfExpression)
    assert isinstance(result.string_set, Identifier)
    assert result.string_set.name == "them"


def test_n_of_with_repeated_them_uses_identifier_node() -> None:
    """n_of() with multiple 'them' args (all equal) must still resolve to Identifier."""
    result = ConditionBuilder().n_of(2, "them", "them").build()
    assert isinstance(result, OfExpression)
    assert isinstance(result.string_set, Identifier)


# ---------------------------------------------------------------------------
# for_all()  (lines 324-327)
# ---------------------------------------------------------------------------


def test_for_all_produces_for_expression_with_all_quantifier() -> None:
    """for_all() must produce a ForExpression with quantifier='all'."""
    iterable = ConditionBuilder().range(0, 5)
    body = ConditionBuilder().identifier("i").gt(0)
    result = ConditionBuilder().for_all("i", iterable, body).build()
    assert isinstance(result, ForExpression)
    assert result.quantifier == "all"
    assert result.variable == "i"
    assert isinstance(result.iterable, RangeExpression)


def test_for_all_accepts_raw_expression_arguments() -> None:
    """for_all() must accept raw Expression objects for iterable and body."""
    iterable: Expression = RangeExpression(
        low=IntegerLiteral(value=0), high=IntegerLiteral(value=3)
    )
    body: Expression = BooleanLiteral(value=True)
    result = ConditionBuilder().for_all("x", iterable, body).build()
    assert isinstance(result, ForExpression)
    assert result.quantifier == "all"


# ---------------------------------------------------------------------------
# mul() / div() / mod()  (lines 347, 351, 355)
# ---------------------------------------------------------------------------


def test_mul_produces_multiplication_binary_expression() -> None:
    """mul() must return a BinaryExpression with operator '*'."""
    result = ConditionBuilder().integer(4).mul(2).build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "*"
    assert isinstance(result.left, IntegerLiteral)
    assert result.left.value == 4


def test_div_produces_division_binary_expression() -> None:
    """div() must return a BinaryExpression with the integer-division operator."""
    result = ConditionBuilder().integer(8).div(2).build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "\\"


def test_mod_produces_modulo_binary_expression() -> None:
    """mod() must return a BinaryExpression with operator '%'."""
    result = ConditionBuilder().integer(7).mod(3).build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "%"


# ---------------------------------------------------------------------------
# bitwise_and() / bitwise_or() / bitwise_xor()  (lines 360, 364, 368)
# ---------------------------------------------------------------------------


def test_bitwise_and_produces_correct_binary_expression() -> None:
    """bitwise_and() must return a BinaryExpression with operator '&'."""
    result = ConditionBuilder().integer(0xFF).bitwise_and(0x0F).build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "&"


def test_bitwise_or_produces_correct_binary_expression() -> None:
    """bitwise_or() must return a BinaryExpression with operator '|'."""
    result = ConditionBuilder().integer(0xF0).bitwise_or(0x0F).build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "|"


def test_bitwise_xor_produces_correct_binary_expression() -> None:
    """bitwise_xor() must return a BinaryExpression with operator '^'."""
    result = ConditionBuilder().integer(0xFF).bitwise_xor(0x0F).build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "^"


# ---------------------------------------------------------------------------
# bitwise_not()  (lines 372-376)
# ---------------------------------------------------------------------------


def test_bitwise_not_on_empty_builder_raises_validation_error() -> None:
    """bitwise_not() must raise ValidationError when called on an empty builder."""
    with pytest.raises(ValidationError, match="Cannot apply bitwise NOT to empty expression"):
        ConditionBuilder().bitwise_not()


def test_bitwise_not_produces_unary_expression_with_tilde() -> None:
    """bitwise_not() success path must return UnaryExpression with operator '~'."""
    result = ConditionBuilder().integer(0).bitwise_not().build()
    assert isinstance(result, UnaryExpression)
    assert result.operator == "~"
    assert isinstance(result.operand, IntegerLiteral)


# ---------------------------------------------------------------------------
# shift_left() / shift_right()  (lines 380, 384)
# ---------------------------------------------------------------------------


def test_shift_left_produces_correct_binary_expression() -> None:
    """shift_left() must return a BinaryExpression with operator '<<'."""
    result = ConditionBuilder().integer(1).shift_left(4).build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "<<"
    assert isinstance(result.right, IntegerLiteral)
    assert result.right.value == 4


def test_shift_right_produces_correct_binary_expression() -> None:
    """shift_right() must return a BinaryExpression with operator '>>'."""
    result = ConditionBuilder().integer(16).shift_right(2).build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == ">>"


# ---------------------------------------------------------------------------
# _binary_op() guard on empty builder  (lines 403-404)
# ---------------------------------------------------------------------------


def test_binary_op_guard_on_empty_builder_raises_validation_error() -> None:
    """eq() and ne() must raise ValidationError when the builder holds no expression."""
    with pytest.raises(ValidationError, match="Cannot apply == to empty expression"):
        ConditionBuilder().eq(5)

    with pytest.raises(ValidationError, match="Cannot apply != to empty expression"):
        ConditionBuilder().ne(5)


# ---------------------------------------------------------------------------
# _integer_binary_op() guard on empty builder  (lines 417-418)
# ---------------------------------------------------------------------------


def test_integer_binary_op_guard_on_empty_builder_raises_validation_error() -> None:
    """lt/le/gt/ge/add/sub/mul must raise ValidationError on an empty builder."""
    with pytest.raises(ValidationError, match="Cannot apply < to empty expression"):
        ConditionBuilder().lt(5)

    with pytest.raises(ValidationError, match=r"Cannot apply \+ to empty expression"):
        ConditionBuilder().add(1)


# ---------------------------------------------------------------------------
# _string_binary_op() guard on empty builder  (lines 431-432)
# ---------------------------------------------------------------------------


def test_string_binary_op_guard_on_empty_builder_raises_validation_error() -> None:
    """contains/matches/startswith must raise ValidationError on an empty builder."""
    with pytest.raises(ValidationError, match="Cannot apply contains to empty expression"):
        ConditionBuilder().contains("pattern")

    with pytest.raises(ValidationError, match="Cannot apply matches to empty expression"):
        ConditionBuilder().matches("pattern")

    with pytest.raises(ValidationError, match="Cannot apply startswith to empty expression"):
        ConditionBuilder().startswith("prefix")


# ---------------------------------------------------------------------------
# _to_string_pattern() — ConditionBuilder branch  (lines 459-462)
# ---------------------------------------------------------------------------


def test_to_string_pattern_accepts_non_empty_condition_builder() -> None:
    """_to_string_pattern must extract expression from a populated ConditionBuilder."""
    pattern = ConditionBuilder().identifier("suffix")
    result = ConditionBuilder().identifier("filename").contains(pattern).build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "contains"
    assert isinstance(result.right, Identifier)


def test_to_string_pattern_rejects_empty_condition_builder() -> None:
    """_to_string_pattern must raise ValidationError for an empty ConditionBuilder."""
    with pytest.raises(ValidationError, match="Empty condition builder"):
        ConditionBuilder().identifier("x").contains(ConditionBuilder())


# ---------------------------------------------------------------------------
# _to_string_pattern() — Expression branch  (line 464)
# ---------------------------------------------------------------------------


def test_to_string_pattern_accepts_raw_expression() -> None:
    """_to_string_pattern must pass through a raw Expression unchanged.

    build() deep-copies the tree; assert structural equality rather than identity.
    """
    raw: Expression = StringLiteral(value="raw_pattern")
    result = ConditionBuilder().identifier("filename").contains(raw).build()
    assert isinstance(result, BinaryExpression)
    assert isinstance(result.right, StringLiteral)
    assert result.right.value == "raw_pattern"


# ---------------------------------------------------------------------------
# _to_expression() — empty ConditionBuilder guard  (lines 477-478)
# ---------------------------------------------------------------------------


def test_to_expression_rejects_empty_condition_builder() -> None:
    """_to_expression must raise ValidationError when given an empty ConditionBuilder."""
    with pytest.raises(ValidationError, match="Empty condition builder"):
        ConditionBuilder().for_any("i", ConditionBuilder(), ConditionBuilder().true())


# ---------------------------------------------------------------------------
# _to_expression() — raw Expression branch  (line 481)
# ---------------------------------------------------------------------------


def test_to_expression_accepts_raw_expression() -> None:
    """_to_expression must accept a raw Expression.

    The public signature of range() is int | ConditionBuilder, but the
    internal _to_expression helper handles bare Expression objects too.
    cast() communicates the deliberate type boundary crossing to mypy
    without suppressing any error — the runtime assertion verifies the
    real behavior.

    build() deep-copies the tree; assert structural equality rather than identity.
    """
    raw: Expression = IntegerLiteral(value=5)
    result = ConditionBuilder().range(cast(Any, raw), 10).build()
    assert isinstance(result, RangeExpression)
    assert isinstance(result.low, IntegerLiteral)
    assert result.low.value == 5


# ---------------------------------------------------------------------------
# _to_expression() — dollar-string branch  (lines 489-490)
# ---------------------------------------------------------------------------


def test_to_expression_converts_dollar_string_to_string_identifier() -> None:
    """_to_expression must convert a '$'-prefixed str to StringIdentifier."""
    result = ConditionBuilder().integer(1).eq("$a").build()
    assert isinstance(result, BinaryExpression)
    assert isinstance(result.right, StringIdentifier)
    assert result.right.name == "$a"


def test_to_expression_non_dollar_string_becomes_string_literal() -> None:
    """_to_expression must convert a non-'$' str to StringLiteral."""
    result = ConditionBuilder().identifier("filename").eq("malware").build()
    assert isinstance(result, BinaryExpression)
    assert isinstance(result.right, StringLiteral)
    assert result.right.value == "malware"


# ---------------------------------------------------------------------------
# _to_integer_expression() — empty ConditionBuilder guard  (lines 500-503)
# ---------------------------------------------------------------------------


def test_to_integer_expression_rejects_empty_condition_builder() -> None:
    """_to_integer_expression must raise ValidationError for an empty ConditionBuilder."""
    with pytest.raises(ValidationError, match="Empty condition builder"):
        ConditionBuilder().integer(1).add(ConditionBuilder())


def test_to_integer_expression_non_empty_condition_builder_returns_expression() -> None:
    """_to_integer_expression must extract expression from a non-empty ConditionBuilder."""
    inner = ConditionBuilder().integer(7)
    result = ConditionBuilder().integer(5).add(inner).build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "+"
    assert isinstance(result.right, IntegerLiteral)
    assert result.right.value == 7


# ---------------------------------------------------------------------------
# _to_integer_expression() — raw Expression branch  (line 505)
# ---------------------------------------------------------------------------


def test_to_integer_expression_accepts_raw_expression() -> None:
    """_to_integer_expression must accept a raw Expression.

    The public signature of add() is ConditionBuilder | int, but the
    internal _to_integer_expression helper handles bare Expression objects too.
    cast() communicates the deliberate type boundary crossing to mypy
    without suppressing any error — the runtime assertion verifies the
    real behavior.

    build() deep-copies the tree; assert structural equality rather than identity.
    """
    raw: Expression = IntegerLiteral(value=7)
    result = ConditionBuilder().integer(5).add(cast(Any, raw)).build()
    assert isinstance(result, BinaryExpression)
    assert isinstance(result.right, IntegerLiteral)
    assert result.right.value == 7


# ---------------------------------------------------------------------------
# them() static factory  (line 553)
# ---------------------------------------------------------------------------


def test_them_static_factory_returns_identifier_named_them() -> None:
    """them() must return a ConditionBuilder holding Identifier(name='them')."""
    result = ConditionBuilder.them().build()
    assert isinstance(result, Identifier)
    assert result.name == "them"


def test_them_can_be_combined_in_logical_expressions() -> None:
    """them() result must participate correctly in logical chain."""
    result = ConditionBuilder.them().and_(ConditionBuilder().true()).build()
    assert isinstance(result, BinaryExpression)
    assert result.operator == "and"
    assert isinstance(result.left, Identifier)
    assert result.left.name == "them"


# ---------------------------------------------------------------------------
# Edge-case coverage: bool rejection in _to_integer_expression  (line 506-507)
# ---------------------------------------------------------------------------


def test_boolean_rejected_in_integer_position_for_shift() -> None:
    """Shift operators must reject bool values via _integer_literal's bool guard."""
    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().integer(1).shift_left(cast(Any, True))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().integer(1).shift_right(cast(Any, False))


def test_boolean_rejected_in_bitwise_operations() -> None:
    """Bitwise operators must reject bool values."""
    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().integer(1).bitwise_and(cast(Any, True))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().integer(1).bitwise_or(cast(Any, False))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().integer(1).bitwise_xor(cast(Any, True))


def test_boolean_rejected_in_mul_div_mod() -> None:
    """Arithmetic operators must reject bool values via _integer_literal."""
    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().integer(1).mul(cast(Any, True))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().integer(1).div(cast(Any, False))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        ConditionBuilder().integer(1).mod(cast(Any, True))
