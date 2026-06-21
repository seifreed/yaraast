# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Coverage regression tests for yaraast.ast.expressions.

Each test exercises a real code path through actual class construction
and method dispatch — no mocks, stubs, or placeholder assertions.
"""

import math
from typing import Any

import pytest

from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    RegexLiteral,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
    UnaryExpression,
    _constant_range_integer_value,
    _is_definitely_boolean_expression,
    _is_definitely_non_integer_range_bound,
    _is_definitely_non_numeric_expression,
    _is_invalid_string_binary_left_operand,
    _is_invalid_string_binary_right_operand,
    _normalize_range_int64,
    _range_integer_remainder,
    _range_shift_left_int64,
    _range_shift_right_int64,
    _receiver_base_and_members,
    _receiver_identifier_path,
    _require_expression,
    _unwrap_parentheses_expression,
    _validate_expression,
    _validate_expression_identifier,
    _validate_integer_expression,
    _validate_regex_text,
    _validate_string_reference_suffix,
)
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.yarax.ast_nodes import TupleExpression, WithStatement

# ---------------------------------------------------------------------------
# Helpers — build minimal AST nodes without boilerplate
# ---------------------------------------------------------------------------


def int_lit(n: int) -> IntegerLiteral:
    return IntegerLiteral(n)


def bool_lit(v: bool) -> BooleanLiteral:
    return BooleanLiteral(v)


def str_lit(s: str) -> StringLiteral:
    return StringLiteral(s)


def dbl_lit(v: float) -> DoubleLiteral:
    return DoubleLiteral(v)


def regex_lit(pattern: str, modifiers: str = "") -> RegexLiteral:
    return RegexLiteral(pattern, modifiers)


def ident(name: str) -> Identifier:
    return Identifier(name)


def str_id(name: str) -> StringIdentifier:
    return StringIdentifier(name)


def binary(left: Expression, op: str, right: Expression) -> BinaryExpression:
    return BinaryExpression(left, op, right)


def unary(op: str, operand: Expression) -> UnaryExpression:
    return UnaryExpression(op, operand)


def paren(expr: Expression) -> ParenthesesExpression:
    return ParenthesesExpression(expr)


# ---------------------------------------------------------------------------
# _validate_expression_identifier (lines 78-88)
# ---------------------------------------------------------------------------


def test_validate_expression_identifier_rejects_non_string() -> None:
    """Non-string argument raises TypeError (line 80-81)."""
    with pytest.raises(TypeError, match="Identifier name must be a string"):
        _validate_expression_identifier(123)


def test_validate_expression_identifier_returns_valid_name() -> None:
    """A valid YARA identifier is returned unchanged (line 83)."""
    assert _validate_expression_identifier("valid_name") == "valid_name"


def test_validate_expression_identifier_accepts_dollar_prefix() -> None:
    """A dollar-prefixed string identifier is normalised and returned (line 84-86)."""
    result = _validate_expression_identifier("$abc")
    assert result == "$abc"


def test_validate_expression_identifier_rejects_invalid_name() -> None:
    """An identifier that is neither a YARA name nor $-prefixed raises ValueError (lines 87-88)."""
    with pytest.raises(ValueError, match="Invalid identifier"):
        _validate_expression_identifier("bad-name!")


# ---------------------------------------------------------------------------
# _validate_string_reference_suffix (lines 91-98)
# ---------------------------------------------------------------------------


def test_validate_string_reference_suffix_rejects_hash_prefix() -> None:
    """# prefix raises ValueError (lines 93-95)."""
    with pytest.raises(ValueError, match="Invalid string reference"):
        _validate_string_reference_suffix("#a")


def test_validate_string_reference_suffix_rejects_at_prefix() -> None:
    """@ prefix raises ValueError (lines 93-95)."""
    with pytest.raises(ValueError, match="Invalid string reference"):
        _validate_string_reference_suffix("@a")


def test_validate_string_reference_suffix_rejects_bang_prefix() -> None:
    """! prefix raises ValueError (lines 93-95)."""
    with pytest.raises(ValueError, match="Invalid string reference"):
        _validate_string_reference_suffix("!a")


def test_validate_string_reference_suffix_accepts_dollar_wildcard() -> None:
    """Bare $ is the wildcard sentinel and returns without normalisation (lines 96-97)."""
    _validate_string_reference_suffix("$")  # must not raise


def test_validate_string_reference_suffix_normalises_valid_ref() -> None:
    """A valid $-prefixed reference is normalised (line 98)."""
    _validate_string_reference_suffix("$abc")  # must not raise


# ---------------------------------------------------------------------------
# _validate_regex_text (lines 101-111)
# ---------------------------------------------------------------------------


def test_validate_regex_text_rejects_surrogate_codepoint() -> None:
    """Unicode surrogate code points raise ValueError (lines 102-104)."""
    with pytest.raises(ValueError, match="surrogate"):
        _validate_regex_text("abc\ud800def")


def test_validate_regex_text_rejects_newline() -> None:
    """Line break in regex pattern raises ValueError (lines 105-107)."""
    with pytest.raises(ValueError, match="line break"):
        _validate_regex_text("abc\ndef")


def test_validate_regex_text_rejects_nul_byte() -> None:
    """NUL byte in regex pattern raises ValueError (lines 108-110)."""
    with pytest.raises(ValueError, match="NUL"):
        _validate_regex_text("abc\x00def")


def test_validate_regex_text_accepts_valid_pattern() -> None:
    """A plain ASCII pattern passes all checks (line 111 — validate_regex_pattern called)."""
    _validate_regex_text("foo.*bar")  # must not raise


# ---------------------------------------------------------------------------
# _normalize_range_int64 (lines 114-118)
# ---------------------------------------------------------------------------


def test_normalize_range_int64_wraps_overflow() -> None:
    """Values above INT64_MAX are wrapped to the signed range (lines 116-117)."""
    result = _normalize_range_int64(1 << 63)
    assert result == -(1 << 63)


def test_normalize_range_int64_identity_for_non_overflow() -> None:
    """Values within the unsigned range that are <= INT64_MAX are unchanged (line 118)."""
    assert _normalize_range_int64(42) == 42


# ---------------------------------------------------------------------------
# _range_integer_remainder (lines 121-125)
# ---------------------------------------------------------------------------


def test_range_integer_remainder_negative_left() -> None:
    """Sign of remainder follows the dividend when left is negative (lines 123-124)."""
    assert _range_integer_remainder(-7, 3) == -1


def test_range_integer_remainder_negative_right() -> None:
    """Sign of remainder follows the dividend when right is negative (lines 123-124)."""
    assert _range_integer_remainder(7, -3) == 1


def test_range_integer_remainder_both_positive() -> None:
    """Both positive inputs produce a standard remainder (line 125)."""
    assert _range_integer_remainder(10, 3) == 1


# ---------------------------------------------------------------------------
# _range_shift_left_int64 (lines 128-131)
# ---------------------------------------------------------------------------


def test_range_shift_left_returns_zero_when_shift_gte_64() -> None:
    """Shift amount >= 64 returns 0 (line 129-130)."""
    assert _range_shift_left_int64(5, 64) == 0
    assert _range_shift_left_int64(5, 100) == 0


def test_range_shift_left_applies_normalised_shift() -> None:
    """Normal shift wraps into the int64 domain (line 131)."""
    assert _range_shift_left_int64(1, 2) == 4


# ---------------------------------------------------------------------------
# _range_shift_right_int64 (lines 134-137)
# ---------------------------------------------------------------------------


def test_range_shift_right_returns_zero_when_shift_gte_64() -> None:
    """Shift amount >= 64 returns 0 (lines 135-136)."""
    assert _range_shift_right_int64(5, 64) == 0
    assert _range_shift_right_int64(5, 100) == 0


def test_range_shift_right_applies_shift() -> None:
    """Normal right shift is applied after normalising the left operand (line 137)."""
    assert _range_shift_right_int64(8, 1) == 4


# ---------------------------------------------------------------------------
# _is_definitely_non_integer_range_bound (lines 140-171)
# ---------------------------------------------------------------------------


def test_non_integer_range_bound_parens_wrapping_integer() -> None:
    """ParenthesesExpression wrapping an integer literal is NOT non-integer (line 149-150)."""
    assert not _is_definitely_non_integer_range_bound(paren(int_lit(5)))


def test_non_integer_range_bound_at_expression() -> None:
    """AtExpression is definitely non-integer (line 151-152)."""
    at = AtExpression(string_id="$a", offset=int_lit(5))
    assert _is_definitely_non_integer_range_bound(at)


def test_non_integer_range_bound_for_expression() -> None:
    """ForExpression is definitely non-integer (line 151-152)."""
    fe = ForExpression(quantifier="all", variable="x", iterable=int_lit(5), body=bool_lit(True))
    assert _is_definitely_non_integer_range_bound(fe)


def test_non_integer_range_bound_of_expression() -> None:
    """OfExpression is definitely non-integer (line 151-152)."""
    sw = StringWildcard("$a*")
    of = OfExpression(quantifier="all", string_set=SetExpression([sw]))
    assert _is_definitely_non_integer_range_bound(of)


def test_non_integer_range_bound_for_of_expression() -> None:
    """ForOfExpression is definitely non-integer (line 151-152)."""
    sw = StringWildcard("$a*")
    foe = ForOfExpression(
        quantifier="all",
        string_set=SetExpression([sw]),
        condition=bool_lit(True),
    )
    assert _is_definitely_non_integer_range_bound(foe)


def test_non_integer_range_bound_in_expression_with_string_count() -> None:
    """InExpression whose subject is a StringCount is NOT non-integer (line 153-154)."""
    sc = StringCount("$a")
    rng = RangeExpression(int_lit(0), int_lit(10))
    ie = InExpression(subject=sc, range=rng)
    assert not _is_definitely_non_integer_range_bound(ie)


def test_non_integer_range_bound_in_expression_with_string_id() -> None:
    """InExpression whose subject is StringIdentifier IS non-integer (line 153-154)."""
    rng = RangeExpression(int_lit(0), int_lit(10))
    ie = InExpression(subject=str_id("$a"), range=rng)
    assert _is_definitely_non_integer_range_bound(ie)


def test_non_integer_range_bound_binary_non_integer_operator() -> None:
    """BinaryExpression with a comparison operator is non-integer (line 156-157)."""
    assert _is_definitely_non_integer_range_bound(binary(int_lit(5), "==", int_lit(5)))


def test_non_integer_range_bound_binary_division() -> None:
    """BinaryExpression with '/' is non-integer (line 158-159)."""
    assert _is_definitely_non_integer_range_bound(binary(int_lit(5), "/", int_lit(2)))


def test_non_integer_range_bound_binary_integer_op_non_integer_left() -> None:
    """'+' with non-integer left operand is non-integer (line 160-163)."""
    assert _is_definitely_non_integer_range_bound(binary(bool_lit(True), "+", int_lit(5)))


def test_non_integer_range_bound_binary_integer_op_non_integer_right() -> None:
    """'+' with non-integer right operand is non-integer (line 160-163)."""
    assert _is_definitely_non_integer_range_bound(binary(int_lit(5), "+", bool_lit(True)))


def test_non_integer_range_bound_binary_integer_op_both_integers() -> None:
    """'+' with two integer literals is NOT non-integer (line 164)."""
    assert not _is_definitely_non_integer_range_bound(binary(int_lit(5), "+", int_lit(3)))


def test_non_integer_range_bound_unary_minus_bool() -> None:
    """Unary '-' wrapping a boolean is non-integer via recursion (lines 165-167)."""
    assert _is_definitely_non_integer_range_bound(unary("-", bool_lit(True)))


def test_non_integer_range_bound_unary_tilde_bool() -> None:
    """Unary '~' wrapping a boolean is non-integer via recursion (lines 165-167)."""
    assert _is_definitely_non_integer_range_bound(unary("~", bool_lit(True)))


def test_non_integer_range_bound_unary_percent() -> None:
    """Unary '%' is always non-integer (line 168)."""
    assert _is_definitely_non_integer_range_bound(unary("%", int_lit(5)))


def test_non_integer_range_bound_unary_not() -> None:
    """Unary 'not' is always non-integer (line 168)."""
    assert _is_definitely_non_integer_range_bound(unary("not", bool_lit(True)))


def test_non_integer_range_bound_boolean_literal() -> None:
    """BooleanLiteral is non-integer (lines 169-171)."""
    assert _is_definitely_non_integer_range_bound(bool_lit(True))


def test_non_integer_range_bound_double_literal() -> None:
    """DoubleLiteral is non-integer (lines 169-171)."""
    assert _is_definitely_non_integer_range_bound(dbl_lit(3.14))


def test_non_integer_range_bound_string_literal() -> None:
    """StringLiteral is non-integer (lines 169-171)."""
    assert _is_definitely_non_integer_range_bound(str_lit("hello"))


def test_non_integer_range_bound_regex_literal() -> None:
    """RegexLiteral is non-integer (lines 169-171)."""
    assert _is_definitely_non_integer_range_bound(regex_lit("foo"))


def test_non_integer_range_bound_string_identifier() -> None:
    """StringIdentifier is non-integer (lines 169-171)."""
    assert _is_definitely_non_integer_range_bound(str_id("$a"))


# ---------------------------------------------------------------------------
# _is_definitely_non_numeric_expression (lines 174-201)
# ---------------------------------------------------------------------------


def test_non_numeric_parens_wrapping_numeric() -> None:
    """ParenthesesExpression wrapping an integer is NOT non-numeric (line 183-184)."""
    assert not _is_definitely_non_numeric_expression(paren(int_lit(5)))


def test_non_numeric_at_expression() -> None:
    """AtExpression is non-numeric (line 185-186)."""
    at = AtExpression(string_id="$a", offset=int_lit(5))
    assert _is_definitely_non_numeric_expression(at)


def test_non_numeric_for_expression() -> None:
    """ForExpression is non-numeric (line 185-186)."""
    fe = ForExpression(quantifier="all", variable="x", iterable=int_lit(5), body=bool_lit(True))
    assert _is_definitely_non_numeric_expression(fe)


def test_non_numeric_of_expression() -> None:
    """OfExpression is non-numeric (line 185-186)."""
    sw = StringWildcard("$a*")
    of = OfExpression(quantifier="all", string_set=SetExpression([sw]))
    assert _is_definitely_non_numeric_expression(of)


def test_non_numeric_in_expression_string_id() -> None:
    """InExpression with non-StringCount subject is non-numeric (lines 187-188)."""
    rng = RangeExpression(int_lit(0), int_lit(10))
    ie = InExpression(subject=str_id("$a"), range=rng)
    assert _is_definitely_non_numeric_expression(ie)


def test_non_numeric_in_expression_string_count() -> None:
    """InExpression with StringCount subject is NOT non-numeric (lines 187-188)."""
    rng = RangeExpression(int_lit(0), int_lit(10))
    ie = InExpression(subject=StringCount("$a"), range=rng)
    assert not _is_definitely_non_numeric_expression(ie)


def test_non_numeric_unary_not() -> None:
    """Unary 'not' is non-numeric (lines 189-191)."""
    assert _is_definitely_non_numeric_expression(unary("not", bool_lit(True)))


def test_non_numeric_unary_percent() -> None:
    """Unary '%' is non-numeric (lines 189-191)."""
    assert _is_definitely_non_numeric_expression(unary("%", int_lit(5)))


def test_non_numeric_unary_minus_wrapping_bool() -> None:
    """Unary '-' wrapping a boolean is non-numeric via recursion (line 192)."""
    assert _is_definitely_non_numeric_expression(unary("-", bool_lit(True)))


def test_non_numeric_binary_comparison() -> None:
    """BinaryExpression with comparison operator is non-numeric (lines 193-195)."""
    assert _is_definitely_non_numeric_expression(binary(int_lit(5), "==", int_lit(5)))


def test_non_numeric_binary_integer_op_non_numeric_left() -> None:
    """'+' with non-numeric left propagates non-numeric (lines 196-199)."""
    assert _is_definitely_non_numeric_expression(binary(bool_lit(True), "+", int_lit(5)))


def test_non_numeric_binary_integer_op_both_numeric_returns_false() -> None:
    """'+' is in _RANGE_INTEGER_BINARY_OPERATORS so the recursion at lines 196-199
    is evaluated for both operands; both IntegerLiterals return False, so the
    combined 'or' is False — confirming '+' with integer operands is NOT classified
    as definitely non-numeric.  Line 200 is unreachable because every valid binary
    operator belongs to one of the two checked sets."""
    result = _is_definitely_non_numeric_expression(binary(int_lit(5), "+", int_lit(3)))
    assert result is False


def test_non_numeric_boolean_literal() -> None:
    """BooleanLiteral is non-numeric (line 201)."""
    assert _is_definitely_non_numeric_expression(bool_lit(False))


def test_non_numeric_string_literal() -> None:
    """StringLiteral is non-numeric (line 201)."""
    assert _is_definitely_non_numeric_expression(str_lit("x"))


def test_non_numeric_regex_literal() -> None:
    """RegexLiteral is non-numeric (line 201)."""
    assert _is_definitely_non_numeric_expression(regex_lit("abc"))


def test_non_numeric_string_identifier() -> None:
    """StringIdentifier is non-numeric (line 201)."""
    assert _is_definitely_non_numeric_expression(str_id("$a"))


def test_non_numeric_double_literal_is_not_non_numeric() -> None:
    """DoubleLiteral is NOT in the non-numeric terminal check (line 201 — excluded)."""
    assert not _is_definitely_non_numeric_expression(dbl_lit(3.14))


# ---------------------------------------------------------------------------
# _constant_range_integer_value (lines 204-253)
# ---------------------------------------------------------------------------


def test_constant_range_value_integer_literal() -> None:
    """IntegerLiteral returns its integer value (lines 205-210)."""
    assert _constant_range_integer_value(int_lit(7)) == 7


def test_constant_range_value_bool_literal_returns_none() -> None:
    """Bool is an int subtype; check excludes it and returns None (lines 205-210)."""
    assert _constant_range_integer_value(BooleanLiteral(True)) is None


def test_constant_range_value_paren_wrapping_int() -> None:
    """ParenthesesExpression passes through to the wrapped literal (lines 211-212)."""
    assert _constant_range_integer_value(paren(int_lit(3))) == 3


def test_constant_range_value_unary_minus() -> None:
    """Unary '-' negates and normalises (lines 213-218)."""
    assert _constant_range_integer_value(unary("-", int_lit(5))) == -5


def test_constant_range_value_unary_tilde() -> None:
    """Unary '~' bitwise-negates and normalises (lines 219-220)."""
    assert _constant_range_integer_value(unary("~", int_lit(5))) == ~5


def test_constant_range_value_unary_percent_returns_none() -> None:
    """Unary '%' is not handled and returns None (line 221)."""
    assert _constant_range_integer_value(unary("%", int_lit(5))) is None


def test_constant_range_value_unary_none_operand() -> None:
    """Unary with a non-constant operand short-circuits to None (lines 214-216)."""
    assert _constant_range_integer_value(unary("-", dbl_lit(3.14))) is None


def test_constant_range_value_non_binary_returns_none() -> None:
    """A non-BinaryExpression that is not Int/Paren/Unary returns None (lines 222-226)."""
    assert _constant_range_integer_value(dbl_lit(3.14)) is None


def test_constant_range_value_binary_operator_not_in_set_returns_none() -> None:
    """BinaryExpression with '/' is not in RANGE_INTEGER_BINARY_OPERATORS (lines 222-226)."""
    assert _constant_range_integer_value(binary(int_lit(5), "/", int_lit(2))) is None


def test_constant_range_value_binary_left_none_short_circuits() -> None:
    """None left operand short-circuits (lines 228-230)."""
    be = binary(dbl_lit(1.0), "+", int_lit(2))
    assert _constant_range_integer_value(be) is None


def test_constant_range_value_binary_right_none_short_circuits() -> None:
    """None right operand short-circuits (lines 228-230)."""
    be = binary(int_lit(2), "+", dbl_lit(1.0))
    assert _constant_range_integer_value(be) is None


def test_constant_range_value_binary_add() -> None:
    """BinaryExpression '+' sums left and right (line 231-232)."""
    assert _constant_range_integer_value(binary(int_lit(3), "+", int_lit(4))) == 7


def test_constant_range_value_binary_subtract() -> None:
    """BinaryExpression '-' subtracts right from left (lines 233-234)."""
    assert _constant_range_integer_value(binary(int_lit(5), "-", int_lit(3))) == 2


def test_constant_range_value_binary_multiply() -> None:
    """BinaryExpression '*' multiplies (lines 235-236)."""
    assert _constant_range_integer_value(binary(int_lit(3), "*", int_lit(4))) == 12


def test_constant_range_value_binary_modulo_zero_right_returns_none() -> None:
    """Modulo by zero returns None (lines 237-239)."""
    assert _constant_range_integer_value(binary(int_lit(5), "%", int_lit(0))) is None


def test_constant_range_value_binary_modulo() -> None:
    """Modulo by non-zero returns remainder (line 240)."""
    assert _constant_range_integer_value(binary(int_lit(7), "%", int_lit(3))) == 1


def test_constant_range_value_binary_bitwise_and() -> None:
    """BinaryExpression '&' (lines 241-242)."""
    assert _constant_range_integer_value(binary(int_lit(5), "&", int_lit(3))) == 1


def test_constant_range_value_binary_bitwise_or() -> None:
    """BinaryExpression '|' (lines 243-244)."""
    assert _constant_range_integer_value(binary(int_lit(5), "|", int_lit(3))) == 7


def test_constant_range_value_binary_bitwise_xor() -> None:
    """BinaryExpression '^' (lines 245-246)."""
    assert _constant_range_integer_value(binary(int_lit(5), "^", int_lit(3))) == 6


def test_constant_range_value_binary_shift_negative_right_returns_none() -> None:
    """Shift with negative right operand returns None (lines 247-248)."""
    assert _constant_range_integer_value(binary(int_lit(5), "<<", int_lit(-1))) is None
    assert _constant_range_integer_value(binary(int_lit(5), ">>", int_lit(-1))) is None


def test_constant_range_value_binary_shift_left() -> None:
    """BinaryExpression '<<' applies left shift (lines 249-250)."""
    assert _constant_range_integer_value(binary(int_lit(1), "<<", int_lit(3))) == 8


def test_constant_range_value_binary_shift_right() -> None:
    """BinaryExpression '>>' applies right shift (lines 251-252)."""
    assert _constant_range_integer_value(binary(int_lit(8), ">>", int_lit(2))) == 2


# ---------------------------------------------------------------------------
# _is_definitely_boolean_expression (lines 262-271)
# ---------------------------------------------------------------------------


def test_is_definitely_boolean_paren_wrapping_bool() -> None:
    """ParenthesesExpression wrapping a BooleanLiteral is boolean (lines 263-264)."""
    assert _is_definitely_boolean_expression(paren(bool_lit(True)))


def test_is_definitely_boolean_literal() -> None:
    """BooleanLiteral is boolean (lines 265-266)."""
    assert _is_definitely_boolean_expression(bool_lit(False))


def test_is_definitely_boolean_unary_not() -> None:
    """Unary 'not' is boolean (lines 267-268)."""
    assert _is_definitely_boolean_expression(unary("not", bool_lit(True)))


def test_is_definitely_boolean_unary_minus_is_not_boolean() -> None:
    """Unary '-' is NOT boolean (lines 267-268)."""
    assert not _is_definitely_boolean_expression(unary("-", int_lit(5)))


def test_is_definitely_boolean_binary_comparison() -> None:
    """BinaryExpression with '==' is boolean (lines 269-270)."""
    assert _is_definitely_boolean_expression(binary(int_lit(5), "==", int_lit(5)))


def test_is_definitely_boolean_binary_arithmetic_is_not_boolean() -> None:
    """BinaryExpression with '+' is NOT boolean (lines 269-270)."""
    assert not _is_definitely_boolean_expression(binary(int_lit(5), "+", int_lit(5)))


def test_is_definitely_boolean_integer_literal_is_not_boolean() -> None:
    """IntegerLiteral is NOT boolean (line 271)."""
    assert not _is_definitely_boolean_expression(int_lit(5))


# ---------------------------------------------------------------------------
# _validate_non_boolean_expression (lines 274-277) — exercised via node validation
# ---------------------------------------------------------------------------


def test_string_offset_boolean_index_raises() -> None:
    """StringOffset.validate_structure rejects a BooleanLiteral index (lines 275-277)."""
    so = StringOffset("$a", index=bool_lit(True))
    with pytest.raises(ValueError, match="boolean"):
        so.validate_structure()


def test_string_length_boolean_index_raises() -> None:
    """StringLength.validate_structure rejects a BooleanLiteral index (lines 275-277)."""
    sl = StringLength("$a", index=bool_lit(True))
    with pytest.raises(ValueError, match="boolean"):
        sl.validate_structure()


# ---------------------------------------------------------------------------
# _is_invalid_string_binary_left_operand (lines 280-286)
# ---------------------------------------------------------------------------


def test_invalid_string_left_boolean_literal() -> None:
    """BooleanLiteral is an invalid string binary left operand (lines 283-286)."""
    assert _is_invalid_string_binary_left_operand(bool_lit(True))


def test_invalid_string_left_integer_literal() -> None:
    """IntegerLiteral is an invalid string binary left operand (lines 283-285)."""
    assert _is_invalid_string_binary_left_operand(int_lit(5))


def test_invalid_string_left_double_literal() -> None:
    """DoubleLiteral is an invalid string binary left operand (lines 283-285)."""
    assert _is_invalid_string_binary_left_operand(dbl_lit(3.14))


def test_invalid_string_left_regex_literal() -> None:
    """RegexLiteral is an invalid string binary left operand (lines 283-285)."""
    assert _is_invalid_string_binary_left_operand(regex_lit("foo"))


def test_invalid_string_left_string_identifier() -> None:
    """StringIdentifier is an invalid string binary left operand (lines 283-285)."""
    assert _is_invalid_string_binary_left_operand(str_id("$a"))


def test_invalid_string_left_double_wrapped_paren_boolean() -> None:
    """Double-parenthesised BooleanLiteral is still an invalid left operand (lines 281-282)."""
    assert _is_invalid_string_binary_left_operand(paren(paren(bool_lit(True))))


def test_valid_string_left_identifier() -> None:
    """Plain Identifier is a valid string binary left operand (lines 283-286 — all False)."""
    assert not _is_invalid_string_binary_left_operand(ident("myvar"))


# ---------------------------------------------------------------------------
# _is_invalid_string_binary_right_operand (lines 289-305)
# ---------------------------------------------------------------------------


def test_invalid_string_right_matches_parenthesised_regex() -> None:
    """Parenthesised RegexLiteral is invalid right operand for 'matches' (lines 293-295)."""
    assert _is_invalid_string_binary_right_operand(paren(regex_lit("foo")), "matches")


def test_valid_string_right_matches_unparenthesised_regex() -> None:
    """Un-parenthesised RegexLiteral is a valid right operand for 'matches' (line 293-295)."""
    assert not _is_invalid_string_binary_right_operand(regex_lit("foo"), "matches")


def test_invalid_string_right_matches_string_literal() -> None:
    """StringLiteral is invalid right operand for 'matches' (lines 296-299)."""
    assert _is_invalid_string_binary_right_operand(str_lit("x"), "matches")


def test_invalid_string_right_matches_boolean() -> None:
    """BooleanLiteral is invalid right operand for 'matches' via _is_definitely_boolean (line 300)."""
    assert _is_invalid_string_binary_right_operand(bool_lit(True), "matches")


def test_invalid_string_right_contains_regex() -> None:
    """RegexLiteral is invalid right operand for non-matches string operators (lines 302-305)."""
    assert _is_invalid_string_binary_right_operand(regex_lit("foo"), "contains")


def test_invalid_string_right_contains_integer() -> None:
    """IntegerLiteral is invalid right operand for non-matches operators (lines 302-305)."""
    assert _is_invalid_string_binary_right_operand(int_lit(5), "contains")


def test_invalid_string_right_contains_boolean_via_bool_check() -> None:
    """BooleanLiteral is invalid right operand for 'contains' via boolean check (lines 302-305)."""
    assert _is_invalid_string_binary_right_operand(bool_lit(False), "contains")


# ---------------------------------------------------------------------------
# Expression.accept (line 325-326)
# ---------------------------------------------------------------------------


def test_expression_base_accept_dispatches_to_visitor() -> None:
    """Expression.accept calls visitor.visit_expression (lines 325-326)."""

    class SimpleVisitor:
        def visit_expression(self, node: Expression) -> str:
            return "visited"

    expr = Expression()
    assert expr.accept(SimpleVisitor()) == "visited"


# ---------------------------------------------------------------------------
# _require_expression (lines 329-333)
# ---------------------------------------------------------------------------


def test_require_expression_rejects_non_expression() -> None:
    """Non-Expression argument raises TypeError (lines 331-332)."""
    with pytest.raises(TypeError, match="must be an Expression"):
        _require_expression("not_an_expr", "my_field")


def test_require_expression_returns_expression() -> None:
    """Valid Expression is returned as-is (line 333)."""
    expr = int_lit(5)
    assert _require_expression(expr, "field") is expr


# ---------------------------------------------------------------------------
# _validate_expression (lines 336-341)
# ---------------------------------------------------------------------------


def test_validate_expression_calls_validate_structure() -> None:
    """_validate_expression invokes validate_structure when present (line 339->341)."""

    class ValidExpr(Expression):
        called: bool = False

        def validate_structure(self) -> None:
            object.__setattr__(self, "called", True)

        def accept(self, visitor: Any) -> Any:
            return None

    ve = ValidExpr()
    _validate_expression(ve, "field")
    assert ve.called


def test_validate_expression_without_validate_structure() -> None:
    """_validate_expression works when validate_structure is absent (line 339->341 branch)."""

    class NoValExpr(Expression):
        def accept(self, visitor: Any) -> Any:
            return None

    nve = NoValExpr()
    result = _validate_expression(nve, "field")
    assert result is nve


def test_validate_expression_propagates_validate_structure_error() -> None:
    """Errors from validate_structure propagate through _validate_expression (lines 340-341)."""

    class BadExpr(Expression):
        def validate_structure(self) -> None:
            raise ValueError("broken")

        def accept(self, visitor: Any) -> Any:
            return None

    with pytest.raises(ValueError, match="broken"):
        _validate_expression(BadExpr(), "field")


# ---------------------------------------------------------------------------
# _unwrap_parentheses_expression (lines 344-347)
# ---------------------------------------------------------------------------


def test_unwrap_single_paren() -> None:
    """Single ParenthesesExpression is unwrapped to its inner expression (lines 345-347)."""
    inner = int_lit(5)
    result = _unwrap_parentheses_expression(paren(inner))
    assert isinstance(result, IntegerLiteral)
    assert result.value == 5


def test_unwrap_double_paren() -> None:
    """Double ParenthesesExpression is fully unwrapped (lines 345-347)."""
    inner = int_lit(3)
    result = _unwrap_parentheses_expression(paren(paren(inner)))
    assert result is inner


def test_unwrap_non_paren_is_identity() -> None:
    """Non-ParenthesesExpression is returned unchanged (lines 344-347)."""
    lit = int_lit(5)
    assert _unwrap_parentheses_expression(lit) is lit


# ---------------------------------------------------------------------------
# StringIdentifier.validate_structure (lines 371-375)
# ---------------------------------------------------------------------------


def test_string_identifier_dollar_sentinel_skips_normalisation() -> None:
    """StringIdentifier with name='$' exits validate_structure early (line 374->exit)."""
    si = str_id("$")
    si.validate_structure()  # must not raise


def test_string_identifier_valid_name_normalises() -> None:
    """StringIdentifier with a valid $-prefixed name succeeds (line 375)."""
    si = str_id("$abc")
    si.validate_structure()  # must not raise


def test_string_identifier_accept() -> None:
    """StringIdentifier.accept dispatches to visit_string_identifier (line 377-378)."""

    class V:
        def visit_string_identifier(self, node: StringIdentifier) -> str:
            return f"si:{node.name}"

    assert str_id("$x").accept(V()) == "si:$x"


# ---------------------------------------------------------------------------
# StringWildcard.validate_structure (lines 387-393)
# ---------------------------------------------------------------------------


def test_string_wildcard_validates_ok() -> None:
    """StringWildcard with a valid wildcard pattern passes validation (lines 389-390)."""
    sw = StringWildcard("$a*")
    sw.validate_structure()  # must not raise


def test_string_wildcard_accept() -> None:
    """StringWildcard.accept dispatches to visit_string_wildcard (line 392-393)."""

    class V:
        def visit_string_wildcard(self, node: StringWildcard) -> str:
            return f"sw:{node.pattern}"

    assert StringWildcard("$x*").accept(V()) == "sw:$x*"


# ---------------------------------------------------------------------------
# StringCount.validate_structure (lines 403-408)
# ---------------------------------------------------------------------------


def test_string_count_validates_ok() -> None:
    """StringCount with a valid reference id passes validation (lines 404-405)."""
    sc = StringCount("$a")
    sc.validate_structure()  # must not raise


def test_string_count_dollar_sentinel() -> None:
    """StringCount with '$' (wildcard sentinel) passes validation (line 408)."""
    sc = StringCount("$")
    sc.validate_structure()  # must not raise


def test_string_count_accept() -> None:
    """StringCount.accept dispatches to visit_string_count (line 407-408)."""

    class V:
        def visit_string_count(self, node: StringCount) -> str:
            return f"sc:{node.string_id}"

    assert StringCount("$a").accept(V()) == "sc:$a"


# ---------------------------------------------------------------------------
# StringOffset.validate_structure (lines 419-427)
# ---------------------------------------------------------------------------


def test_string_offset_without_index() -> None:
    """StringOffset with no index passes validation (lines 420-421)."""
    so = StringOffset("$a")
    so.validate_structure()  # must not raise


def test_string_offset_with_valid_integer_index() -> None:
    """StringOffset with an IntegerLiteral index passes validation (lines 422-424)."""
    so = StringOffset("$a", index=int_lit(5))
    so.validate_structure()  # must not raise


def test_string_offset_accept() -> None:
    """StringOffset.accept dispatches to visit_string_offset (lines 426-427)."""

    class V:
        def visit_string_offset(self, node: StringOffset) -> str:
            return f"so:{node.string_id}"

    assert StringOffset("$a").accept(V()) == "so:$a"


# ---------------------------------------------------------------------------
# StringLength.validate_structure (lines 438-446)
# ---------------------------------------------------------------------------


def test_string_length_without_index() -> None:
    """StringLength with no index passes validation (lines 439-440)."""
    sl = StringLength("$a")
    sl.validate_structure()  # must not raise


def test_string_length_with_valid_integer_index() -> None:
    """StringLength with an IntegerLiteral index passes validation (lines 441-443)."""
    sl = StringLength("$a", index=int_lit(2))
    sl.validate_structure()  # must not raise


def test_string_length_accept() -> None:
    """StringLength.accept dispatches to visit_string_length (lines 445-446)."""

    class V:
        def visit_string_length(self, node: StringLength) -> str:
            return f"sl:{node.string_id}"

    assert StringLength("$a").accept(V()) == "sl:$a"


# ---------------------------------------------------------------------------
# IntegerLiteral.validate_structure (lines 454-462)
# ---------------------------------------------------------------------------


def test_integer_literal_bool_value_raises() -> None:
    """IntegerLiteral whose value is a bool raises TypeError (lines 457-459)."""
    with pytest.raises(TypeError, match="Integer literal value must be an integer"):
        IntegerLiteral(True).validate_structure()


def test_integer_literal_string_value_raises() -> None:
    """IntegerLiteral whose value is a str raises TypeError (lines 457-459)."""
    with pytest.raises(TypeError, match="Integer literal value must be an integer"):
        IntegerLiteral("five").validate_structure()  # type: ignore[arg-type]


def test_integer_literal_valid_value_passes() -> None:
    """IntegerLiteral with a genuine int passes validation."""
    IntegerLiteral(42).validate_structure()  # must not raise


# ---------------------------------------------------------------------------
# DoubleLiteral.validate_structure (lines 470-481)
# ---------------------------------------------------------------------------


def test_double_literal_bool_value_raises() -> None:
    """DoubleLiteral whose value is a bool raises TypeError (lines 473-475)."""
    with pytest.raises(TypeError, match="Double literal value must be numeric"):
        DoubleLiteral(True).validate_structure()


def test_double_literal_string_value_raises() -> None:
    """DoubleLiteral whose value is a str raises TypeError (lines 473-475)."""
    with pytest.raises(TypeError, match="Double literal value must be numeric"):
        DoubleLiteral("pi").validate_structure()  # type: ignore[arg-type]


def test_double_literal_inf_raises() -> None:
    """DoubleLiteral with math.inf raises ValueError (lines 476-478)."""
    with pytest.raises(ValueError, match="finite"):
        DoubleLiteral(math.inf).validate_structure()


def test_double_literal_nan_raises() -> None:
    """DoubleLiteral with math.nan raises ValueError (lines 476-478)."""
    with pytest.raises(ValueError, match="finite"):
        DoubleLiteral(math.nan).validate_structure()


def test_double_literal_valid_passes() -> None:
    """DoubleLiteral with a finite float passes validation."""
    DoubleLiteral(3.14).validate_structure()  # must not raise


# ---------------------------------------------------------------------------
# StringLiteral.validate_structure (lines 490-497)
# ---------------------------------------------------------------------------


def test_string_literal_non_string_value_raises() -> None:
    """StringLiteral with a non-string value raises TypeError (lines 492-494)."""
    with pytest.raises(TypeError, match="String literal value must be a string"):
        StringLiteral(42).validate_structure()  # type: ignore[arg-type]


def test_string_literal_valid_passes() -> None:
    """StringLiteral with a string value passes validation."""
    StringLiteral("hello").validate_structure()  # must not raise


# ---------------------------------------------------------------------------
# RegexLiteral.validate_structure (lines 506-522)
# ---------------------------------------------------------------------------


def test_regex_literal_non_string_pattern_raises() -> None:
    """RegexLiteral with non-string pattern raises TypeError (lines 509-511)."""
    with pytest.raises(TypeError, match="Regex literal pattern must be a string"):
        RegexLiteral(42).validate_structure()  # type: ignore[arg-type]


def test_regex_literal_empty_pattern_raises() -> None:
    """RegexLiteral with empty pattern raises ValueError (lines 512-514)."""
    with pytest.raises(ValueError, match="must not be empty"):
        RegexLiteral("").validate_structure()


def test_regex_literal_non_string_modifiers_raises() -> None:
    """RegexLiteral with non-string modifiers raises TypeError (lines 515-517)."""
    with pytest.raises(TypeError, match="Regex literal modifiers must be a string"):
        RegexLiteral("foo", 42).validate_structure()  # type: ignore[arg-type]


def test_regex_literal_valid_passes() -> None:
    """RegexLiteral with valid pattern and modifiers passes (lines 518-519)."""
    RegexLiteral("foo.*bar", "i").validate_structure()  # must not raise


# ---------------------------------------------------------------------------
# BooleanLiteral.validate_structure (lines 530-538)
# ---------------------------------------------------------------------------


def test_boolean_literal_non_bool_raises() -> None:
    """BooleanLiteral with non-bool value raises TypeError (lines 533-535)."""
    with pytest.raises(TypeError, match="Boolean literal value must be a boolean"):
        BooleanLiteral(1).validate_structure()  # type: ignore[arg-type]


def test_boolean_literal_valid_passes() -> None:
    """BooleanLiteral with a genuine bool passes validation."""
    BooleanLiteral(False).validate_structure()  # must not raise


# ---------------------------------------------------------------------------
# BinaryExpression.validate_structure (lines 549-578)
# ---------------------------------------------------------------------------


def test_binary_expression_invalid_operator_raises() -> None:
    """BinaryExpression with an unknown operator raises ValueError (lines 553-555)."""
    with pytest.raises(ValueError, match="Invalid binary operator"):
        binary(int_lit(5), "INVALID", int_lit(5)).validate_structure()


def test_binary_expression_numeric_op_non_numeric_left_raises() -> None:
    """'+' with a boolean left operand raises ValueError (lines 557-560)."""
    with pytest.raises(ValueError, match="Left operand of '\\+' must be numeric"):
        binary(bool_lit(True), "+", int_lit(5)).validate_structure()


def test_binary_expression_numeric_op_non_numeric_right_raises() -> None:
    """'+' with a boolean right operand raises ValueError (lines 561-563)."""
    with pytest.raises(ValueError, match="Right operand of '\\+' must be numeric"):
        binary(int_lit(5), "+", bool_lit(True)).validate_structure()


def test_binary_expression_integer_op_non_integer_left_raises() -> None:
    """'&' with a boolean left operand raises ValueError (lines 564-567)."""
    with pytest.raises(ValueError, match="Left operand of '&' must be integer"):
        binary(bool_lit(True), "&", int_lit(5)).validate_structure()


def test_binary_expression_integer_op_non_integer_right_raises() -> None:
    """'&' with a boolean right operand raises ValueError (lines 568-570)."""
    with pytest.raises(ValueError, match="Right operand of '&' must be integer"):
        binary(int_lit(5), "&", bool_lit(True)).validate_structure()


def test_binary_expression_string_op_invalid_left_raises() -> None:
    """'contains' with integer left operand raises ValueError (lines 571-574)."""
    with pytest.raises(ValueError, match="Left operand of 'contains' must be string"):
        binary(int_lit(5), "contains", str_lit("foo")).validate_structure()


def test_binary_expression_string_op_invalid_right_raises() -> None:
    """'contains' with integer right operand raises ValueError (lines 575-578)."""
    with pytest.raises(ValueError, match="Right operand of 'contains' must be string"):
        binary(ident("x"), "contains", int_lit(5)).validate_structure()


def test_binary_expression_matches_invalid_right_raises() -> None:
    """'matches' with StringLiteral right operand raises ValueError (lines 575-578)."""
    with pytest.raises(ValueError, match="Right operand of 'matches' must be regex"):
        binary(ident("x"), "matches", str_lit("foo")).validate_structure()


def test_binary_expression_valid_passes() -> None:
    """A well-formed BinaryExpression passes validation."""
    binary(int_lit(3), "+", int_lit(4)).validate_structure()  # must not raise


# ---------------------------------------------------------------------------
# UnaryExpression.validate_structure (lines 591-606)
# ---------------------------------------------------------------------------


def test_unary_expression_invalid_operator_raises() -> None:
    """UnaryExpression with unknown operator raises ValueError (lines 594-596)."""
    with pytest.raises(ValueError, match="Invalid unary operator"):
        unary("INVALID", int_lit(5)).validate_structure()


def test_unary_expression_minus_non_numeric_raises() -> None:
    """Unary '-' with a boolean operand raises ValueError (lines 598-600)."""
    with pytest.raises(ValueError, match="must be numeric"):
        unary("-", bool_lit(True)).validate_structure()


def test_unary_expression_tilde_non_integer_raises() -> None:
    """Unary '~' with a boolean operand raises ValueError (lines 601-603)."""
    with pytest.raises(ValueError, match="must be integer"):
        unary("~", bool_lit(True)).validate_structure()


def test_unary_expression_valid_passes() -> None:
    """A well-formed UnaryExpression passes validation."""
    unary("-", int_lit(5)).validate_structure()  # must not raise


def test_unary_expression_accept() -> None:
    """UnaryExpression.accept dispatches to visit_unary_expression (line 605-606)."""

    class V:
        def visit_unary_expression(self, node: UnaryExpression) -> str:
            return f"ue:{node.operator}"

    assert unary("not", bool_lit(False)).accept(V()) == "ue:not"


# ---------------------------------------------------------------------------
# SetExpression.validate_structure (lines 628-641)
# ---------------------------------------------------------------------------


def test_set_expression_non_list_raises() -> None:
    """SetExpression with a non-list elements raises TypeError (lines 631-636)."""
    with pytest.raises(TypeError, match="list or tuple"):
        SetExpression("bad").validate_structure()  # type: ignore[arg-type]


def test_set_expression_with_invalid_element_propagates() -> None:
    """SetExpression whose element fails validate_structure propagates the error (line 637-638)."""
    bad = BooleanLiteral(True)
    bad.value = 99  # type: ignore[assignment]  # corrupt to force TypeError
    with pytest.raises(TypeError):
        SetExpression([bad]).validate_structure()


def test_set_expression_valid_passes() -> None:
    """SetExpression with valid Expression elements passes validation."""
    SetExpression([int_lit(1), int_lit(2)]).validate_structure()  # must not raise


# ---------------------------------------------------------------------------
# FunctionCall.validate_structure (lines 679-697)
# ---------------------------------------------------------------------------


def test_function_call_receiver_at_expression_raises() -> None:
    """FunctionCall with AtExpression receiver raises ValueError (lines 692-697)."""
    at = AtExpression(string_id="$a", offset=int_lit(5))
    with pytest.raises(ValueError, match="must not be an 'at' or 'with' expression"):
        FunctionCall("foo", [], receiver=at).validate_structure()


def test_function_call_receiver_with_statement_raises() -> None:
    """FunctionCall with WithStatement receiver raises ValueError (lines 692-697)."""
    ws = WithStatement(declarations=[], body=bool_lit(True))
    with pytest.raises(ValueError, match="must not be an 'at' or 'with' expression"):
        FunctionCall("foo", [], receiver=ws).validate_structure()


def test_function_call_qualified_name_with_receiver() -> None:
    """qualified_name() includes the receiver path (lines 702-707)."""
    ma = MemberAccess(ident("pe"), "signatures")
    fc = FunctionCall("valid_on", [int_lit(1)], receiver=ma)
    assert fc.qualified_name() == "pe.signatures.valid_on"


def test_function_call_qualified_name_no_receiver() -> None:
    """qualified_name() returns the plain function name when receiver is None (lines 704-705)."""
    fc = FunctionCall("uint16", [int_lit(0)])
    assert fc.qualified_name() == "uint16"


def test_function_call_qualified_name_receiver_with_no_path() -> None:
    """qualified_name() falls back to function name when receiver path is None (line 707)."""
    fc = FunctionCall("foo", [], receiver=bool_lit(True))
    assert fc.qualified_name() == "foo"


def test_function_call_module_and_function_dotted_no_receiver() -> None:
    """Dotted function name without receiver resolves to (module, func) (lines 715-718)."""
    fc = FunctionCall("pe.imphash", [])
    assert fc.module_and_function() == ("pe", "imphash")


def test_function_call_module_and_function_unqualified_returns_none() -> None:
    """Unqualified name without receiver returns None (line 719)."""
    fc = FunctionCall("uint16", [int_lit(0)])
    assert fc.module_and_function() is None


def test_function_call_module_and_function_with_receiver() -> None:
    """Receiver-based call resolves to (module, function_key) (lines 720-723)."""
    arr = ArrayAccess(MemberAccess(ident("pe"), "signatures"), int_lit(0))
    fc = FunctionCall("valid_on", [int_lit(1)], receiver=arr)
    assert fc.module_and_function() == ("pe", "signatures.valid_on")


def test_function_call_module_and_function_no_base_returns_none() -> None:
    """Receiver that cannot be resolved to a base returns None (line 722)."""
    fc = FunctionCall("foo", [], receiver=bool_lit(True))
    assert fc.module_and_function() is None


def test_function_call_module_and_function_module_reference_receiver() -> None:
    """ModuleReference receiver is resolved correctly (lines 720-723)."""
    mod = ModuleReference("pe")
    fc = FunctionCall("imphash", [], receiver=mod)
    assert fc.module_and_function() == ("pe", "imphash")


# ---------------------------------------------------------------------------
# _receiver_base_and_members (lines 726-749)
# ---------------------------------------------------------------------------


def test_receiver_base_and_members_member_access() -> None:
    """MemberAccess traversal accumulates member names (lines 737-739)."""
    ma = MemberAccess(ident("pe"), "signatures")
    assert _receiver_base_and_members(ma) == ("pe", ["signatures"])


def test_receiver_base_and_members_array_access_drops_index() -> None:
    """ArrayAccess traversal skips the index (lines 740-741)."""
    ma = MemberAccess(ident("pe"), "signatures")
    aa = ArrayAccess(ma, int_lit(0))
    assert _receiver_base_and_members(aa) == ("pe", ["signatures"])


def test_receiver_base_and_members_dictionary_access_drops_key() -> None:
    """DictionaryAccess traversal skips the key (lines 742-743)."""
    da = DictionaryAccess(ident("pe"), str_lit("key"))
    assert _receiver_base_and_members(da) == ("pe", [])


def test_receiver_base_and_members_identifier_terminal() -> None:
    """Identifier terminates traversal and returns the base name (lines 744-745)."""
    assert _receiver_base_and_members(ident("pe")) == ("pe", [])


def test_receiver_base_and_members_module_reference_terminal() -> None:
    """ModuleReference terminates traversal and returns the module name (lines 746-747)."""
    assert _receiver_base_and_members(ModuleReference("pe")) == ("pe", [])


def test_receiver_base_and_members_unknown_returns_none() -> None:
    """Unsupported expression returns (None, []) (lines 748-749)."""
    assert _receiver_base_and_members(bool_lit(True)) == (None, [])


def test_receiver_base_and_members_chained() -> None:
    """Chained MemberAccess → ArrayAccess → DictionaryAccess is fully unwound (lines 737-747)."""
    ma1 = MemberAccess(ident("pe"), "sigs")
    aa = ArrayAccess(ma1, int_lit(0))
    da = DictionaryAccess(aa, str_lit("k"))
    ma2 = MemberAccess(da, "valid_on")
    assert _receiver_base_and_members(ma2) == ("pe", ["sigs", "valid_on"])


# ---------------------------------------------------------------------------
# _receiver_identifier_path (lines 752-756)
# ---------------------------------------------------------------------------


def test_receiver_identifier_path_none_base_returns_none() -> None:
    """When base is None the path is None (lines 753-754)."""
    assert _receiver_identifier_path(bool_lit(True)) is None


def test_receiver_identifier_path_no_members() -> None:
    """When there are no members the path is just the base name (lines 755-756)."""
    assert _receiver_identifier_path(ident("pe")) == "pe"


def test_receiver_identifier_path_with_members() -> None:
    """When there are members the path is dotted (lines 755-756)."""
    ma = MemberAccess(ident("pe"), "signatures")
    assert _receiver_identifier_path(ma) == "pe.signatures"


# ---------------------------------------------------------------------------
# ArrayAccess.validate_structure (lines 766-781)
# ---------------------------------------------------------------------------


def test_array_access_module_reference_raises() -> None:
    """ArrayAccess whose array is a ModuleReference raises ValueError (lines 776-777)."""
    with pytest.raises(ValueError, match="module reference"):
        ArrayAccess(ModuleReference("pe"), int_lit(0)).validate_structure()


def test_array_access_tuple_expression_raises() -> None:
    """ArrayAccess whose array is a TupleExpression raises ValueError (lines 778-779)."""
    tup = TupleExpression(elements=[int_lit(1), int_lit(2)])
    with pytest.raises(ValueError, match="tuple expression"):
        ArrayAccess(tup, int_lit(0)).validate_structure()


def test_array_access_at_expression_raises() -> None:
    """ArrayAccess whose array is an AtExpression raises ValueError (lines 780-781)."""
    at = AtExpression(string_id="$a", offset=int_lit(5))
    with pytest.raises(ValueError, match="'at' or 'with'"):
        ArrayAccess(at, int_lit(0)).validate_structure()


def test_array_access_valid_passes() -> None:
    """ArrayAccess with valid Identifier array and IntegerLiteral index passes (line 784)."""
    ArrayAccess(ident("items"), int_lit(0)).validate_structure()  # must not raise


def test_array_access_accept() -> None:
    """ArrayAccess.accept dispatches to visit_array_access (line 783-784)."""

    class V:
        def visit_array_access(self, node: ArrayAccess) -> str:
            return "aa"

    assert ArrayAccess(ident("arr"), int_lit(0)).accept(V()) == "aa"


# ---------------------------------------------------------------------------
# MemberAccess.validate_structure (lines 793-803)
# ---------------------------------------------------------------------------


def test_member_access_at_expression_object_raises() -> None:
    """MemberAccess whose object is an AtExpression raises ValueError (lines 801-803)."""
    at = AtExpression(string_id="$a", offset=int_lit(5))
    with pytest.raises(ValueError, match="'at' or 'with'"):
        MemberAccess(at, "field").validate_structure()


def test_member_access_with_statement_object_raises() -> None:
    """MemberAccess whose object is a WithStatement raises ValueError (lines 801-803)."""
    ws = WithStatement(declarations=[], body=bool_lit(True))
    with pytest.raises(ValueError, match="'at' or 'with'"):
        MemberAccess(ws, "field").validate_structure()


def test_member_access_valid_passes() -> None:
    """MemberAccess with a valid Identifier object and member name passes validation."""
    MemberAccess(ident("pe"), "imphash").validate_structure()  # must not raise


def test_member_access_accept() -> None:
    """MemberAccess.accept dispatches to visit_member_access (line 805-806)."""

    class V:
        def visit_member_access(self, node: MemberAccess) -> str:
            return f"ma:{node.member}"

    assert MemberAccess(ident("pe"), "version").accept(V()) == "ma:version"


# ---------------------------------------------------------------------------
# _is_definitely_non_integer_range_bound: integer-op both-integer branch (line 164)
# ---------------------------------------------------------------------------


def test_non_integer_range_bound_binary_integer_op_both_integer_is_false() -> None:
    """BinaryExpression '+' with two IntegerLiterals returns False (line 164).

    The recursive check at lines 160-163 evaluates both operands; neither is
    non-integer so the combined 'or' is False, returning False at line 164."""
    result = _is_definitely_non_integer_range_bound(binary(int_lit(5), "+", int_lit(3)))
    assert result is False


# ---------------------------------------------------------------------------
# _validate_integer_expression (lines 256-259)
# ---------------------------------------------------------------------------


def test_validate_integer_expression_raises_for_non_integer() -> None:
    """_validate_integer_expression raises ValueError for a BooleanLiteral (lines 258-259)."""
    with pytest.raises(ValueError, match="must be integer"):
        _validate_integer_expression(bool_lit(True), "test field")


# ---------------------------------------------------------------------------
# _validate_constant_range_bounds (lines 308-318) — direct calls
# ---------------------------------------------------------------------------


def test_validate_constant_range_bounds_both_non_constant_passes() -> None:
    """When neither bound is a constant integer the function returns immediately (lines 309-312)."""
    from yaraast.ast.expressions import _validate_constant_range_bounds as vcr

    vcr(ident("x"), ident("y"))  # must not raise


def test_validate_constant_range_bounds_negative_low_raises() -> None:
    """A constant negative low bound raises ValueError (lines 313-315)."""
    from yaraast.ast.expressions import _validate_constant_range_bounds as vcr

    with pytest.raises(ValueError, match="cannot be negative"):
        vcr(int_lit(-1), int_lit(10))


def test_validate_constant_range_bounds_low_exceeds_high_raises() -> None:
    """A constant low bound exceeding the high bound raises ValueError (lines 316-318)."""
    from yaraast.ast.expressions import _validate_constant_range_bounds as vcr

    with pytest.raises(ValueError, match="cannot exceed high bound"):
        vcr(int_lit(10), int_lit(5))


def test_validate_constant_range_bounds_valid_passes() -> None:
    """Equal low and high constant bounds pass validation."""
    from yaraast.ast.expressions import _validate_constant_range_bounds as vcr

    vcr(int_lit(5), int_lit(5))  # must not raise


# ---------------------------------------------------------------------------
# Identifier.accept (line 362)
# ---------------------------------------------------------------------------


def test_identifier_accept_dispatches() -> None:
    """Identifier.accept dispatches to visit_identifier (line 362)."""

    class V:
        def visit_identifier(self, node: Identifier) -> str:
            return f"id:{node.name}"

    assert ident("myvar").accept(V()) == "id:myvar"


# ---------------------------------------------------------------------------
# IntegerLiteral.accept (line 462)
# ---------------------------------------------------------------------------


def test_integer_literal_accept_dispatches() -> None:
    """IntegerLiteral.accept dispatches to visit_integer_literal (line 462)."""

    class V:
        def visit_integer_literal(self, node: IntegerLiteral) -> str:
            return f"int:{node.value}"

    assert int_lit(42).accept(V()) == "int:42"


# ---------------------------------------------------------------------------
# DoubleLiteral.accept (line 481)
# ---------------------------------------------------------------------------


def test_double_literal_accept_dispatches() -> None:
    """DoubleLiteral.accept dispatches to visit_double_literal (line 481)."""

    class V:
        def visit_double_literal(self, node: DoubleLiteral) -> str:
            return f"dbl:{node.value}"

    assert dbl_lit(3.14).accept(V()) == "dbl:3.14"


# ---------------------------------------------------------------------------
# StringLiteral.accept (line 497)
# ---------------------------------------------------------------------------


def test_string_literal_accept_dispatches() -> None:
    """StringLiteral.accept dispatches to visit_string_literal (line 497)."""

    class V:
        def visit_string_literal(self, node: StringLiteral) -> str:
            return f"sl:{node.value}"

    assert str_lit("hello").accept(V()) == "sl:hello"


# ---------------------------------------------------------------------------
# RegexLiteral.accept (line 522)
# ---------------------------------------------------------------------------


def test_regex_literal_accept_dispatches() -> None:
    """RegexLiteral.accept dispatches to visit_regex_literal (line 522)."""

    class V:
        def visit_regex_literal(self, node: RegexLiteral) -> str:
            return f"rl:{node.pattern}"

    assert regex_lit("foo.*").accept(V()) == "rl:foo.*"


# ---------------------------------------------------------------------------
# BooleanLiteral.accept (line 538)
# ---------------------------------------------------------------------------


def test_boolean_literal_accept_dispatches() -> None:
    """BooleanLiteral.accept dispatches to visit_boolean_literal (line 538)."""

    class V:
        def visit_boolean_literal(self, node: BooleanLiteral) -> str:
            return f"bl:{node.value}"

    assert bool_lit(True).accept(V()) == "bl:True"


# ---------------------------------------------------------------------------
# BinaryExpression.accept (line 581)
# ---------------------------------------------------------------------------


def test_binary_expression_accept_dispatches() -> None:
    """BinaryExpression.accept dispatches to visit_binary_expression (line 581)."""

    class V:
        def visit_binary_expression(self, node: BinaryExpression) -> str:
            return f"be:{node.operator}"

    assert binary(int_lit(1), "+", int_lit(2)).accept(V()) == "be:+"


# ---------------------------------------------------------------------------
# ParenthesesExpression.validate_structure and accept (lines 616-620)
# ---------------------------------------------------------------------------


def test_parentheses_expression_validate_structure_passes() -> None:
    """ParenthesesExpression.validate_structure with a valid inner expression (line 617)."""
    ParenthesesExpression(int_lit(5)).validate_structure()  # must not raise


def test_parentheses_expression_accept_dispatches() -> None:
    """ParenthesesExpression.accept dispatches to visit_parentheses_expression (line 620)."""

    class V:
        def visit_parentheses_expression(self, node: ParenthesesExpression) -> str:
            return "pe"

    assert paren(int_lit(5)).accept(V()) == "pe"


# ---------------------------------------------------------------------------
# SetExpression.accept (line 641)
# ---------------------------------------------------------------------------


def test_set_expression_accept_dispatches() -> None:
    """SetExpression.accept dispatches to visit_set_expression (line 641)."""

    class V:
        def visit_set_expression(self, node: SetExpression) -> str:
            return f"se:{len(node.elements)}"

    assert SetExpression([int_lit(1), int_lit(2)]).accept(V()) == "se:2"


# ---------------------------------------------------------------------------
# RangeExpression.validate_structure and accept (lines 651-660)
# ---------------------------------------------------------------------------


def test_range_expression_validate_structure_passes() -> None:
    """RangeExpression.validate_structure with valid integer bounds (lines 653-657)."""
    RangeExpression(int_lit(0), int_lit(10)).validate_structure()  # must not raise


def test_range_expression_accept_dispatches() -> None:
    """RangeExpression.accept dispatches to visit_range_expression (line 660)."""

    class V:
        def visit_range_expression(self, node: RangeExpression) -> str:
            return "re"

    assert RangeExpression(int_lit(0), int_lit(10)).accept(V()) == "re"


# ---------------------------------------------------------------------------
# FunctionCall.validate_structure with arguments (line 688-689) and accept (line 700)
# ---------------------------------------------------------------------------


def test_function_call_with_arguments_validates() -> None:
    """FunctionCall.validate_structure iterates over arguments (line 689)."""
    fc = FunctionCall("strlen", [str_lit("hello"), int_lit(0)])
    fc.validate_structure()  # must not raise


def test_function_call_accept_dispatches() -> None:
    """FunctionCall.accept dispatches to visit_function_call (line 700)."""

    class V:
        def visit_function_call(self, node: FunctionCall) -> str:
            return f"fc:{node.function}"

    assert FunctionCall("uint16", [int_lit(0)]).accept(V()) == "fc:uint16"


# ---------------------------------------------------------------------------
# Branch coverage: BinaryExpression.validate_structure happy-path branches
# ---------------------------------------------------------------------------


def test_binary_expression_integer_op_valid_operands_branch_568_to_571() -> None:
    """BinaryExpression '&' with valid integer operands: both checks pass (branch 568->571).

    This exercises the path where right-operand integer check at line 568 is False
    (the right operand IS integer), so execution continues to the string-op block
    at line 571 without raising.  '&' is not a string operator so the whole
    validate_structure succeeds."""
    binary(int_lit(5), "&", int_lit(3)).validate_structure()  # must not raise


def test_binary_expression_string_op_valid_operands_branch_575_to_exit() -> None:
    """BinaryExpression 'contains' with valid operands: right-operand check at line 575 is False.

    When _is_invalid_string_binary_right_operand returns False the function exits
    normally (branch 575->exit) without raising."""
    binary(ident("x"), "contains", str_lit("needle")).validate_structure()  # must not raise


def test_binary_expression_matches_valid_regex_right_branch_575_to_exit() -> None:
    """BinaryExpression 'matches' with an un-parenthesised RegexLiteral is valid (branch 575->exit)."""
    binary(ident("x"), "matches", regex_lit("foo.*")).validate_structure()  # must not raise


# ---------------------------------------------------------------------------
# Branch coverage: FunctionCall.validate_structure valid-receiver branch (696->exit)
# ---------------------------------------------------------------------------


def test_function_call_valid_receiver_passes_branch_696_to_exit() -> None:
    """FunctionCall with a valid MemberAccess receiver exits the receiver check normally.

    Line 696 checks isinstance(receiver, AtExpression | WithStatement) — when this
    is False (a normal receiver) execution falls through to the end of the method
    (branch 696->exit) without raising."""
    fc = FunctionCall(
        "valid_on",
        [int_lit(1)],
        receiver=MemberAccess(ident("pe"), "signatures"),
    )
    fc.validate_structure()  # must not raise


def test_function_call_identifier_receiver_passes_branch_696_to_exit() -> None:
    """FunctionCall with a plain Identifier receiver also takes the valid branch (696->exit)."""
    fc = FunctionCall("imphash", [], receiver=ident("pe"))
    fc.validate_structure()  # must not raise
