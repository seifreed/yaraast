# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage tests for yaraast.ast.conditions missing branches.

Each test exercises a real production code path by constructing actual AST
node objects and calling their real methods.  No mocks, no stubs, no
placeholder implementations.

Missing lines targeted (from --cov-report=term-missing baseline):
    34->36, 46, 49, 62, 69-83, 101, 107, 131-132, 199, 207, 209,
    242-243, 289
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from yaraast.ast.conditions import (
    AtExpression,
    Condition,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
    _classify_string_set_items,
    _classify_string_set_value,
    _invalid_quantifier,
    _is_definitely_non_for_iterable,
    _is_invalid_for_iterable_set_item,
    _is_percentage_quantifier,
    _validate_consistent_string_set_kind,
    _validate_for_iterable,
    _validate_percentage_quantifier_text,
    _validate_quantifier,
    _validate_quantifier_text,
    _validate_required_expression,
    _validate_restricted_of_expression,
    _validate_string_reference_or_expression,
    _validate_string_set,
    _validate_string_set_text,
)
from yaraast.ast.expressions import (
    BooleanLiteral,
    DoubleLiteral,
    Expression,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    RangeExpression,
    RegexLiteral,
    SetExpression,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
    UnaryExpression,
)

# ---------------------------------------------------------------------------
# Minimal Expression subclass without validate_structure — used to trigger the
# False branch at line 34 (callable(validate_structure) evaluates to False).
# ---------------------------------------------------------------------------


@dataclass
class _BareExpression(Expression):
    """Concrete Expression with no validate_structure method."""

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_expression(self)


# ===========================================================================
# _validate_required_expression
# ===========================================================================


class TestValidateRequiredExpression:
    """Lines 30-36."""

    def test_non_expression_raises_type_error(self) -> None:
        """Line 31-32: not an Expression raises TypeError."""
        with pytest.raises(TypeError, match="must be"):
            _validate_required_expression("not_an_expr", "must be an Expression")

    def test_expression_without_validate_structure_returns_value(self) -> None:
        """Branch 34->36 (False): expression has no callable validate_structure."""
        # _BareExpression has no validate_structure attribute, so getattr returns
        # None, callable(None) is False, we skip line 35 and return at line 36.
        expr = _BareExpression()
        result = _validate_required_expression(expr, "unused")
        assert result is expr

    def test_expression_with_validate_structure_calls_it(self) -> None:
        """Branch 34->35->36 (True): expression has validate_structure, it is called."""
        # IntegerLiteral.validate_structure() accepts a valid int silently.
        expr = IntegerLiteral(value=1)
        result = _validate_required_expression(expr, "unused")
        assert result is expr

    def test_expression_whose_validate_structure_raises_propagates(self) -> None:
        """validate_structure raising is propagated to the caller."""
        # An IntegerLiteral with a boolean value will fail its own validate_structure.
        bad_expr = IntegerLiteral(value=True)
        with pytest.raises(TypeError):
            _validate_required_expression(bad_expr, "should propagate")


# ===========================================================================
# _invalid_quantifier
# ===========================================================================


class TestInvalidQuantifier:
    """Lines 39-41."""

    def test_raises_value_error_with_field_name(self) -> None:
        with pytest.raises(ValueError, match="Invalid myfield '42'"):
            _invalid_quantifier(42, "myfield")

    def test_raises_with_string_value(self) -> None:
        with pytest.raises(ValueError, match="Invalid q 'bad'"):
            _invalid_quantifier("bad", "q")


# ===========================================================================
# _validate_percentage_quantifier_text
# ===========================================================================


class TestValidatePercentageQuantifierText:
    """Lines 44-50."""

    def test_non_percentage_pattern_returns_early(self) -> None:
        """Line 45-46: fullmatch returns None for non-digit% strings; function returns."""
        # '+50%' ends with % so it may be passed here, but regex requires '^\\d+%$'
        # so +50% has no fullmatch -> returns at line 46 without error.
        _validate_percentage_quantifier_text("+50%", "q")

    def test_valid_percentage_returns_without_error(self) -> None:
        """Line 47-49: percent in [1, 100] returns cleanly."""
        _validate_percentage_quantifier_text("50%", "q")
        _validate_percentage_quantifier_text("1%", "q")
        _validate_percentage_quantifier_text("100%", "q")

    def test_zero_percent_raises_invalid_quantifier(self) -> None:
        """Line 50: 0% is out of range [1, 100] -> _invalid_quantifier."""
        with pytest.raises(ValueError, match="Invalid q '0%'"):
            _validate_percentage_quantifier_text("0%", "q")

    def test_one_hundred_one_percent_raises(self) -> None:
        """101% is out of range -> _invalid_quantifier."""
        with pytest.raises(ValueError, match="Invalid q '101%'"):
            _validate_percentage_quantifier_text("101%", "q")


# ===========================================================================
# _validate_quantifier_text
# ===========================================================================


class TestValidateQuantifierText:
    """Lines 53-83."""

    def test_empty_string_raises_value_error(self) -> None:
        """Line 54-56: empty or whitespace-only value raises ValueError."""
        with pytest.raises(ValueError, match="must not be empty"):
            _validate_quantifier_text("", "q", allow_percentage=False)
        with pytest.raises(ValueError, match="must not be empty"):
            _validate_quantifier_text("   ", "q", allow_percentage=False)

    def test_keyword_all_accepted(self) -> None:
        """Line 57-58: 'all', 'any', 'none' are accepted without error."""
        _validate_quantifier_text("all", "q", allow_percentage=False)
        _validate_quantifier_text("any", "q", allow_percentage=False)
        _validate_quantifier_text("none", "q", allow_percentage=False)

    def test_non_negative_integer_string_accepted(self) -> None:
        """Line 59-62: integer string that is >= 0 returns."""
        _validate_quantifier_text("0", "q", allow_percentage=False)
        _validate_quantifier_text("5", "q", allow_percentage=False)

    def test_negative_integer_string_raises(self) -> None:
        """Line 60-62: negative integer string -> _invalid_quantifier (line 62)."""
        with pytest.raises(ValueError, match="Invalid q '-5'"):
            _validate_quantifier_text("-5", "q", allow_percentage=False)

    def test_positive_prefix_integer_string_accepted(self) -> None:
        """Line 63-64: '+N' where N is a non-negative integer is accepted."""
        _validate_quantifier_text("+5", "q", allow_percentage=False)
        _validate_quantifier_text("+0", "q", allow_percentage=False)

    def test_percentage_not_allowed_raises(self) -> None:
        """Line 65-67: value ending with '%' when allow_percentage=False raises."""
        with pytest.raises(ValueError, match="Invalid q '50%'"):
            _validate_quantifier_text("50%", "q", allow_percentage=False)

    def test_valid_percentage_string_accepted_when_allowed(self) -> None:
        """Lines 65-70: valid percent string with allow_percentage=True returns."""
        _validate_quantifier_text("50%", "q", allow_percentage=True)
        _validate_quantifier_text("1%", "q", allow_percentage=True)
        _validate_quantifier_text("100%", "q", allow_percentage=True)

    def test_float_like_string_raises_invalid_quantifier(self) -> None:
        """Lines 71-80: string containing '.', 'e', or 'E' and parses as finite float."""
        with pytest.raises(ValueError, match=r"Invalid q '3\.14'"):
            _validate_quantifier_text("3.14", "q", allow_percentage=False)
        with pytest.raises(ValueError, match="Invalid q '1e2'"):
            _validate_quantifier_text("1e2", "q", allow_percentage=False)
        with pytest.raises(ValueError, match="Invalid q '2E3'"):
            _validate_quantifier_text("2E3", "q", allow_percentage=False)

    def test_non_finite_float_string_raises_value_error(self) -> None:
        """Lines 71-79: string with 'E' that parses as non-finite raises ValueError."""
        with pytest.raises(ValueError, match="must be finite"):
            _validate_quantifier_text("1E500", "q", allow_percentage=False)

    def test_string_with_float_markers_but_not_parseable_then_identifier(self) -> None:
        """Lines 71-75, 81-82: string containing 'e' but not a valid float, then passes
        identifier regex check."""
        # 'xe' contains 'e'; float('xe') raises ValueError (caught at line 74-75).
        # Then _QUANTIFIER_IDENTIFIER_RE.fullmatch('xe') matches -> returns at line 82.
        _validate_quantifier_text("xe", "q", allow_percentage=False)

    def test_identifier_string_accepted(self) -> None:
        """Lines 81-82: valid identifier string is accepted."""
        _validate_quantifier_text("myvar", "q", allow_percentage=False)
        _validate_quantifier_text("Hello", "q", allow_percentage=False)
        _validate_quantifier_text("_under", "q", allow_percentage=False)

    def test_invalid_non_identifier_string_raises(self) -> None:
        """Line 83: string that is not any accepted form -> _invalid_quantifier."""
        with pytest.raises(ValueError, match="Invalid q"):
            _validate_quantifier_text("abc-def", "q", allow_percentage=False)
        with pytest.raises(ValueError, match="Invalid q"):
            _validate_quantifier_text("$abc", "q", allow_percentage=False)


# ===========================================================================
# _validate_quantifier
# ===========================================================================


class TestValidateQuantifier:
    """Lines 86-108."""

    def test_expression_quantifier_accepted(self) -> None:
        """Line 87-89: Expression quantifier delegates to _validate_expression."""
        _validate_quantifier(IntegerLiteral(value=3), "q", allow_percentage=False)

    def test_string_quantifier_delegates_to_text(self) -> None:
        """Line 90-92: string quantifier delegates to _validate_quantifier_text."""
        _validate_quantifier("all", "q", allow_percentage=False)
        _validate_quantifier("5", "q", allow_percentage=False)

    def test_bool_quantifier_raises_type_error(self) -> None:
        """Line 93-95: bool is rejected (isinstance(True, int) is True but bool check first)."""
        with pytest.raises(TypeError, match="must be a string, number, or expression"):
            _validate_quantifier(True, "q", allow_percentage=False)

    def test_non_numeric_non_string_non_expression_raises_type_error(self) -> None:
        """Line 93-95: a list is not str/int/float/Expression -> TypeError."""
        with pytest.raises(TypeError, match="must be a string, number, or expression"):
            _validate_quantifier([], "q", allow_percentage=False)

    def test_non_finite_float_raises_value_error(self) -> None:
        """Line 96-98: float('inf') is not finite -> ValueError."""
        import math

        with pytest.raises(ValueError, match="must be finite"):
            _validate_quantifier(math.inf, "q", allow_percentage=False)

    def test_non_negative_int_accepted(self) -> None:
        """Line 99-102: non-negative int returns normally."""
        _validate_quantifier(0, "q", allow_percentage=False)
        _validate_quantifier(10, "q", allow_percentage=False)

    def test_negative_int_raises(self) -> None:
        """Line 100-101: negative integer -> _invalid_quantifier (line 101)."""
        with pytest.raises(ValueError, match="Invalid q '-3'"):
            _validate_quantifier(-3, "q", allow_percentage=False)

    def test_float_percentage_not_allowed_raises(self) -> None:
        """Line 103-104: float when allow_percentage=False -> _invalid_quantifier."""
        with pytest.raises(ValueError, match=r"Invalid q '0\.5'"):
            _validate_quantifier(0.5, "q", allow_percentage=False)

    def test_float_valid_percentage_range_accepted(self) -> None:
        """Line 105-107: float in (0, 1] maps to percent in [1, 100] -> returns (line 107)."""
        _validate_quantifier(0.5, "q", allow_percentage=True)
        _validate_quantifier(0.01, "q", allow_percentage=True)
        _validate_quantifier(1.0, "q", allow_percentage=True)

    def test_float_out_of_percentage_range_raises(self) -> None:
        """Line 108: percent outside [1, 100] -> _invalid_quantifier."""
        with pytest.raises(ValueError, match=r"Invalid q '0\.0'"):
            _validate_quantifier(0.0, "q", allow_percentage=True)
        with pytest.raises(ValueError, match=r"Invalid q '2\.0'"):
            _validate_quantifier(2.0, "q", allow_percentage=True)


# ===========================================================================
# _validate_string_reference_or_expression
# ===========================================================================


class TestValidateStringReferenceOrExpression:
    """Lines 111-126."""

    def test_expression_accepted(self) -> None:
        _validate_string_reference_or_expression(IntegerLiteral(value=1), "fld", "type error")

    def test_non_string_non_expression_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="type error"):
            _validate_string_reference_or_expression(42, "fld", "type error")

    def test_empty_string_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            _validate_string_reference_or_expression("  ", "fld", "type error")

    def test_dollar_alone_accepted(self) -> None:
        _validate_string_reference_or_expression("$", "fld", "type error")

    def test_valid_string_reference_accepted(self) -> None:
        _validate_string_reference_or_expression("$a", "fld", "type error")


# ===========================================================================
# _validate_string_set_text
# ===========================================================================


class TestValidateStringSetText:
    """Lines 129-135."""

    def test_empty_string_raises_value_error(self) -> None:
        """Line 130-132: empty/whitespace raises ValueError (line 131-132)."""
        with pytest.raises(ValueError, match="must contain values"):
            _validate_string_set_text("", "fld")
        with pytest.raises(ValueError, match="must contain values"):
            _validate_string_set_text("   ", "fld")

    def test_them_keyword_accepted(self) -> None:
        """Lines 133-134: 'them' returns without further validation."""
        _validate_string_set_text("them", "fld")

    def test_valid_wildcard_string_reference_accepted(self) -> None:
        """Line 135: delegates to normalize_string_reference_id with wildcard."""
        _validate_string_set_text("$a*", "fld")
        _validate_string_set_text("$b", "fld")


# ===========================================================================
# _is_percentage_quantifier
# ===========================================================================


class TestIsPercentageQuantifier:
    """Lines 190-210."""

    def test_float_returns_true(self) -> None:
        """Line 198-199: a Python float is always a percentage quantifier."""
        assert _is_percentage_quantifier(0.5) is True
        assert _is_percentage_quantifier(1.0) is True

    def test_int_returns_false(self) -> None:
        assert _is_percentage_quantifier(5) is False

    def test_str_ending_with_percent_returns_true(self) -> None:
        """Line 200-201: string ending with '%'."""
        assert _is_percentage_quantifier("50%") is True

    def test_str_not_ending_with_percent_returns_false(self) -> None:
        assert _is_percentage_quantifier("all") is False

    def test_double_literal_returns_true(self) -> None:
        """Line 202-203: DoubleLiteral is always a percentage quantifier."""
        assert _is_percentage_quantifier(DoubleLiteral(value=0.5)) is True

    def test_string_literal_ending_with_percent_returns_true(self) -> None:
        """Line 204-205: StringLiteral whose value ends with '%'."""
        assert _is_percentage_quantifier(StringLiteral(value="50%")) is True

    def test_string_literal_not_ending_with_percent_returns_false(self) -> None:
        """Line 204-205 (False branch): StringLiteral whose value does not end with '%'."""
        assert _is_percentage_quantifier(StringLiteral(value="hello")) is False

    def test_unary_expression_with_percent_operator_returns_true(self) -> None:
        """Line 206-207: UnaryExpression with operator '%'."""
        ue = UnaryExpression(operator="%", operand=IntegerLiteral(value=50))
        assert _is_percentage_quantifier(ue) is True

    def test_unary_expression_other_operator_returns_false(self) -> None:
        """Line 206 (False branch): UnaryExpression with a non-'%' operator."""
        ue = UnaryExpression(operator="-", operand=IntegerLiteral(value=5))
        assert _is_percentage_quantifier(ue) is False

    def test_parentheses_expression_wrapping_double_literal_returns_true(self) -> None:
        """Line 208-209: ParenthesesExpression delegates to inner value."""
        paren = ParenthesesExpression(expression=DoubleLiteral(value=0.5))
        assert _is_percentage_quantifier(paren) is True

    def test_parentheses_expression_wrapping_non_percentage_returns_false(self) -> None:
        """Line 208-209: ParenthesesExpression wrapping non-percentage."""
        paren = ParenthesesExpression(expression=IntegerLiteral(value=5))
        assert _is_percentage_quantifier(paren) is False

    def test_unrecognized_type_returns_false(self) -> None:
        """Line 210: unrecognized type returns False."""
        assert _is_percentage_quantifier(object()) is False


# ===========================================================================
# _validate_string_set — collection item branches
# ===========================================================================


class TestValidateStringSet:
    """Lines 224-251: collection item validation branches."""

    def test_none_value_raises(self) -> None:
        with pytest.raises(ValueError, match="is required"):
            _validate_string_set(None, "fld")

    def test_dict_value_raises(self) -> None:
        with pytest.raises(ValueError, match="is required"):
            _validate_string_set({}, "fld")

    def test_expression_accepted(self) -> None:
        _validate_string_set(StringLiteral(value="$a"), "fld")

    def test_string_them_accepted(self) -> None:
        _validate_string_set("them", "fld")

    def test_non_collection_non_string_non_expression_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="must be a string, expression, or collection"):
            _validate_string_set(42, "fld")

    def test_empty_collection_raises(self) -> None:
        with pytest.raises(ValueError, match="must contain values"):
            _validate_string_set([], "fld")

    def test_collection_with_none_item_raises(self) -> None:
        """Lines 241-243: item is None -> raises ValueError (line 242-243)."""
        with pytest.raises(ValueError, match="must contain values"):
            _validate_string_set([None], "fld")

    def test_collection_with_dict_item_raises(self) -> None:
        """Lines 241-243: item is a dict -> raises ValueError (line 242-243)."""
        with pytest.raises(ValueError, match="must contain values"):
            _validate_string_set([{}], "fld")

    def test_collection_with_expression_item_accepted(self) -> None:
        """Line 244-246: Expression item is validated and accepted."""
        _validate_string_set([StringLiteral(value="$a")], "fld")

    def test_collection_with_string_item_accepted(self) -> None:
        """Line 247-249: string item delegates to _validate_string_set_text."""
        _validate_string_set(["$a"], "fld")
        _validate_string_set(["them"], "fld")

    def test_collection_with_invalid_type_item_raises_type_error(self) -> None:
        """Line 250-251: item that is not str/Expression/None/dict -> TypeError."""
        with pytest.raises(TypeError, match="must contain strings or expressions"):
            _validate_string_set([123], "fld")


# ===========================================================================
# _is_invalid_for_iterable_set_item — ParenthesesExpression branch
# ===========================================================================


class TestIsInvalidForIterableSetItem:
    """Lines 278-293 (line 289: ParenthesesExpression recursive branch)."""

    def test_boolean_literal_is_invalid(self) -> None:
        assert _is_invalid_for_iterable_set_item(BooleanLiteral(value=True)) is True

    def test_double_literal_is_invalid(self) -> None:
        assert _is_invalid_for_iterable_set_item(DoubleLiteral(value=1.0)) is True

    def test_regex_literal_is_invalid(self) -> None:
        assert _is_invalid_for_iterable_set_item(RegexLiteral(pattern="abc")) is True

    def test_string_identifier_is_invalid(self) -> None:
        assert _is_invalid_for_iterable_set_item(StringIdentifier(name="$a")) is True

    def test_string_wildcard_is_invalid(self) -> None:
        assert _is_invalid_for_iterable_set_item(StringWildcard(pattern="$a*")) is True

    def test_integer_literal_is_valid(self) -> None:
        assert _is_invalid_for_iterable_set_item(IntegerLiteral(value=1)) is False

    def test_parentheses_wrapping_invalid_item_is_invalid(self) -> None:
        """Line 288-289: ParenthesesExpression wrapping invalid item is also invalid."""
        paren = ParenthesesExpression(expression=BooleanLiteral(value=False))
        assert _is_invalid_for_iterable_set_item(paren) is True

    def test_parentheses_wrapping_valid_item_is_valid(self) -> None:
        """Line 288-289: ParenthesesExpression wrapping valid item is valid."""
        paren = ParenthesesExpression(expression=IntegerLiteral(value=1))
        assert _is_invalid_for_iterable_set_item(paren) is False


# ===========================================================================
# _validate_for_iterable — SetExpression with invalid items (line 289 path)
# ===========================================================================


class TestValidateForIterable:
    """Lines 296-306: SetExpression with invalid items triggers line 289 via any()."""

    def test_range_expression_is_valid_iterable(self) -> None:
        r = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10))
        _validate_for_iterable(r)

    def test_non_for_iterable_expression_raises(self) -> None:
        with pytest.raises(ValueError, match="range, set, or iterable"):
            _validate_for_iterable(BooleanLiteral(value=True))

    def test_set_expression_with_boolean_item_raises(self) -> None:
        """Line 302-306: SetExpression containing an invalid item raises ValueError."""
        bad_set = SetExpression(elements=[BooleanLiteral(value=True)])
        with pytest.raises(ValueError, match="integer or string expressions"):
            _validate_for_iterable(bad_set)

    def test_set_expression_with_string_identifier_item_raises(self) -> None:
        """SetExpression containing StringIdentifier is invalid for a for iterable."""
        bad_set = SetExpression(elements=[StringIdentifier(name="$a")])
        with pytest.raises(ValueError, match="integer or string expressions"):
            _validate_for_iterable(bad_set)

    def test_set_expression_with_parentheses_wrapping_invalid_raises(self) -> None:
        """Line 289 is reached via ParenthesesExpression inside SetExpression items."""
        paren_double = ParenthesesExpression(expression=DoubleLiteral(value=1.0))
        bad_set = SetExpression(elements=[paren_double])
        with pytest.raises(ValueError, match="integer or string expressions"):
            _validate_for_iterable(bad_set)

    def test_set_expression_with_integer_items_is_valid(self) -> None:
        """SetExpression with only IntegerLiteral items is a valid for iterable."""
        good_set = SetExpression(elements=[IntegerLiteral(value=1), IntegerLiteral(value=2)])
        _validate_for_iterable(good_set)


# ===========================================================================
# Full node validate_structure integration
# ===========================================================================


class TestForExpressionValidateStructure:
    """ForExpression.validate_structure exercises several helpers in sequence."""

    def test_valid_for_expression_passes(self) -> None:
        r = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10))
        fe = ForExpression(
            quantifier="all",
            variable="i",
            iterable=r,
            body=IntegerLiteral(value=1),
        )
        fe.validate_structure()

    def test_non_string_variable_raises(self) -> None:
        r = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10))
        fe = ForExpression(
            quantifier="all",
            variable=42,  # type: ignore[arg-type]
            iterable=r,
            body=IntegerLiteral(value=1),
        )
        with pytest.raises(TypeError, match="variable must be a string"):
            fe.validate_structure()

    def test_empty_variable_raises(self) -> None:
        r = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10))
        fe = ForExpression(
            quantifier="all",
            variable="",
            iterable=r,
            body=IntegerLiteral(value=1),
        )
        with pytest.raises(ValueError, match="variable must not be empty"):
            fe.validate_structure()

    def test_non_expression_iterable_raises(self) -> None:
        fe = ForExpression(
            quantifier="all",
            variable="i",
            iterable="not_an_expr",  # type: ignore[arg-type]
            body=IntegerLiteral(value=1),
        )
        with pytest.raises(TypeError, match="iterable must be an AST expression"):
            fe.validate_structure()

    def test_non_expression_body_raises(self) -> None:
        r = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10))
        fe = ForExpression(
            quantifier="all",
            variable="i",
            iterable=r,
            body="not_an_expr",  # type: ignore[arg-type]
        )
        with pytest.raises(TypeError, match="body must be an AST expression"):
            fe.validate_structure()

    def test_percentage_quantifier_not_allowed_for_for_expression(self) -> None:
        r = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10))
        fe = ForExpression(
            quantifier="50%",
            variable="i",
            iterable=r,
            body=IntegerLiteral(value=1),
        )
        with pytest.raises(ValueError):
            fe.validate_structure()

    def test_negative_int_quantifier_raises(self) -> None:
        r = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10))
        fe = ForExpression(
            quantifier=-1,
            variable="i",
            iterable=r,
            body=IntegerLiteral(value=1),
        )
        with pytest.raises(ValueError, match="Invalid"):
            fe.validate_structure()


class TestOfExpressionValidateStructure:
    """OfExpression.validate_structure exercises quantifier + string_set validation."""

    def test_valid_of_expression_passes(self) -> None:
        oe = OfExpression(quantifier="all", string_set="them")
        oe.validate_structure()

    def test_percentage_quantifier_accepted(self) -> None:
        oe = OfExpression(quantifier="50%", string_set="them")
        oe.validate_structure()

    def test_float_percentage_quantifier_accepted(self) -> None:
        oe = OfExpression(quantifier=0.5, string_set="them")
        oe.validate_structure()

    def test_invalid_string_set_raises(self) -> None:
        oe = OfExpression(quantifier="all", string_set=None)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="is required"):
            oe.validate_structure()


class TestForOfExpressionValidateStructure:
    """ForOfExpression.validate_structure — percentage allowed only when no condition."""

    def test_valid_for_of_no_condition(self) -> None:
        fo = ForOfExpression(quantifier="any", string_set="them")
        fo.validate_structure()

    def test_percentage_quantifier_allowed_without_condition(self) -> None:
        fo = ForOfExpression(quantifier="50%", string_set="them")
        fo.validate_structure()

    def test_percentage_quantifier_rejected_with_condition(self) -> None:
        """When condition is set, allow_percentage=False."""
        fo = ForOfExpression(
            quantifier="50%",
            string_set="them",
            condition=BooleanLiteral(value=True),
        )
        with pytest.raises(ValueError):
            fo.validate_structure()

    def test_invalid_condition_type_raises(self) -> None:
        fo = ForOfExpression(
            quantifier="any",
            string_set="them",
            condition="not_expr",  # type: ignore[arg-type]
        )
        with pytest.raises(TypeError, match="condition must be an AST expression"):
            fo.validate_structure()


class TestAtExpressionValidateStructure:
    """AtExpression.validate_structure."""

    def test_valid_at_expression_passes(self) -> None:
        ae = AtExpression(string_id="$a", offset=IntegerLiteral(value=0))
        ae.validate_structure()

    def test_invalid_string_id_type_raises(self) -> None:
        ae = AtExpression(string_id=42, offset=IntegerLiteral(value=0))  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="string_id must be a string or expression"):
            ae.validate_structure()

    def test_of_expression_as_string_id_with_percentage_raises(self) -> None:
        """_validate_restricted_of_expression rejects percentage of-expr at AtExpression."""
        oe = OfExpression(quantifier=0.5, string_set="them")
        ae = AtExpression(string_id=oe, offset=IntegerLiteral(value=0))
        with pytest.raises(ValueError, match="Percentage of-expressions"):
            ae.validate_structure()


class TestInExpressionValidateStructure:
    """InExpression.validate_structure and string_id property."""

    def test_valid_in_expression_passes(self) -> None:
        r = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10))
        ie = InExpression(subject="$a", range=r)
        ie.validate_structure()

    def test_string_id_property_returns_string_for_str_subject(self) -> None:
        r = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10))
        ie = InExpression(subject="$a", range=r)
        assert ie.string_id == "$a"

    def test_string_id_property_returns_none_for_expression_subject(self) -> None:
        r = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10))
        ie = InExpression(subject=StringIdentifier(name="$a"), range=r)
        assert ie.string_id is None

    def test_of_expression_with_rule_set_as_subject_raises(self) -> None:
        """Rule sets cannot use at/in restrictions."""
        r = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10))
        oe = OfExpression(quantifier="all", string_set=Identifier(name="myrule"))
        ie = InExpression(subject=oe, range=r)
        with pytest.raises(ValueError, match="Rule sets cannot use at/in restrictions"):
            ie.validate_structure()


class TestConditionAccept:
    """Condition.accept delegates to visitor.visit_condition."""

    def test_condition_accept_calls_visitor(self) -> None:
        class _Recorder:
            called_with: object = None

            def visit_condition(self, node: object) -> str:
                self.called_with = node
                return "visited"

        cond = OfExpression(quantifier="all", string_set="them")
        # Condition.accept is overridden in OfExpression; call base directly.
        visitor = _Recorder()
        result = Condition.accept(cond, visitor)
        assert result == "visited"
        assert visitor.called_with is cond


class TestClassifyStringSetValue:
    """_classify_string_set_value branches."""

    def test_string_value_returns_string(self) -> None:
        assert _classify_string_set_value("$a") == "string"

    def test_string_identifier_returns_string(self) -> None:
        assert _classify_string_set_value(StringIdentifier(name="$a")) == "string"

    def test_string_wildcard_with_dollar_prefix_returns_string(self) -> None:
        assert _classify_string_set_value(StringWildcard(pattern="$a*")) == "string"

    def test_string_wildcard_without_dollar_prefix_returns_rule(self) -> None:
        assert _classify_string_set_value(StringWildcard(pattern="myrule*")) == "rule"

    def test_string_literal_with_str_value_returns_string(self) -> None:
        assert _classify_string_set_value(StringLiteral(value="abc")) == "string"

    def test_identifier_them_returns_string(self) -> None:
        assert _classify_string_set_value(Identifier(name="them")) == "string"

    def test_identifier_dollar_prefix_returns_string(self) -> None:
        assert _classify_string_set_value(Identifier(name="$a")) == "string"

    def test_identifier_other_name_returns_rule(self) -> None:
        assert _classify_string_set_value(Identifier(name="myrule")) == "rule"

    def test_set_expression_delegates_to_items(self) -> None:
        se = SetExpression(elements=[StringIdentifier(name="$a")])
        assert _classify_string_set_value(se) == "string"

    def test_list_delegates_to_items(self) -> None:
        assert _classify_string_set_value(["$a"]) == "string"

    def test_unrecognized_type_returns_none(self) -> None:
        assert _classify_string_set_value(42) is None

    def test_parentheses_wrapping_string_identifier_returns_string(self) -> None:
        paren = ParenthesesExpression(expression=StringIdentifier(name="$a"))
        assert _classify_string_set_value(paren) == "string"


class TestClassifyStringSetItems:
    """_classify_string_set_items mixed-kind detection."""

    def test_empty_list_returns_none_kind(self) -> None:
        assert _classify_string_set_items([]) is None

    def test_uniform_string_items_returns_string(self) -> None:
        assert _classify_string_set_items(["$a", "$b"]) == "string"

    def test_mixed_string_and_rule_returns_mixed(self) -> None:
        items = [StringIdentifier(name="$a"), Identifier(name="myrule")]
        assert _classify_string_set_items(items) == "mixed"

    def test_unrecognized_item_returns_none(self) -> None:
        assert _classify_string_set_items([42]) is None


class TestValidateConsistentStringSetKind:
    """_validate_consistent_string_set_kind."""

    def test_uniform_set_passes(self) -> None:
        _validate_consistent_string_set_kind(["$a", "$b"])

    def test_mixed_set_raises(self) -> None:
        items = [StringIdentifier(name="$a"), Identifier(name="myrule")]
        with pytest.raises(ValueError, match="Mixed string and rule"):
            _validate_consistent_string_set_kind(items)


# ===========================================================================
# _validate_quantifier_text — branch 69->71 (False branch after percent check)
# ===========================================================================


class TestValidateQuantifierTextPercentFalseBranch:
    """Branch 69->71: value ends with '%', allow_percentage=True, PERCENTAGE_RE has no
    fullmatch (e.g. '+50%') — _validate_percentage_quantifier_text returns early, then
    line 69 evaluates to False (no fullmatch), execution falls to line 71."""

    def test_non_standard_percent_string_raises_invalid_quantifier(self) -> None:
        """'+50%' ends with '%', passes allow check, passes percent validation (early return
        at line 46 since regex doesn't match), then fails fullmatch at line 69 -> goes to
        line 71 and eventually raises at line 83 (_invalid_quantifier)."""
        with pytest.raises(ValueError, match="Invalid q"):
            _validate_quantifier_text("+50%", "q", allow_percentage=True)


# ===========================================================================
# _validate_restricted_of_expression — branch 219->exit (normal exit path)
# ===========================================================================


class TestValidateRestrictedOfExpressionNormalExit:
    """Branch 219->exit: OfExpression with non-percentage quantifier and non-rule
    string_set passes both checks and exits normally."""

    def test_non_percentage_non_rule_of_expression_passes(self) -> None:
        """An OfExpression with a plain integer quantifier and 'them' string_set is
        accepted; line 219 evaluates to False and function exits (219->exit branch)."""
        oe = OfExpression(quantifier="all", string_set="them")
        _validate_restricted_of_expression(oe)

    def test_integer_quantifier_with_string_set_passes(self) -> None:
        oe = OfExpression(quantifier=3, string_set=["$a", "$b"])
        _validate_restricted_of_expression(oe)


# ===========================================================================
# _is_definitely_non_for_iterable — line 266 (ParenthesesExpression branch)
# ===========================================================================


class TestIsDefinitelyNonForIterable:
    """Line 265-266: ParenthesesExpression delegates recursively."""

    def test_parentheses_wrapping_boolean_literal_is_non_iterable(self) -> None:
        """Line 265-266: ParenthesesExpression wrapping a BooleanLiteral returns True."""
        paren = ParenthesesExpression(expression=BooleanLiteral(value=True))
        assert _is_definitely_non_for_iterable(paren) is True

    def test_parentheses_wrapping_integer_literal_is_non_iterable(self) -> None:
        """Line 265-266: ParenthesesExpression wrapping an IntegerLiteral returns True."""
        paren = ParenthesesExpression(expression=IntegerLiteral(value=1))
        assert _is_definitely_non_for_iterable(paren) is True

    def test_parentheses_wrapping_iterable_expression_is_not_non_iterable(self) -> None:
        """ParenthesesExpression wrapping an Identifier is NOT definitely non-iterable."""
        paren = ParenthesesExpression(expression=Identifier(name="mylist"))
        assert _is_definitely_non_for_iterable(paren) is False

    def test_paren_wrapping_non_iterable_raises_in_validate_for_iterable(self) -> None:
        """Driving the ParenthesesExpression path in _is_definitely_non_for_iterable
        through _validate_for_iterable ensures line 266 is covered via production call."""
        paren = ParenthesesExpression(expression=BooleanLiteral(value=False))
        with pytest.raises(ValueError, match="range, set, or iterable"):
            _validate_for_iterable(paren)


# ===========================================================================
# accept() methods on concrete condition classes (lines 353, 380, 402, 434, 455)
# ===========================================================================


class _MinimalVisitor:
    """Lightweight visitor that records the last node it received per method."""

    def __init__(self) -> None:
        self.last_node: object = None
        self.last_method: str = ""

    def visit_for_expression(self, node: object) -> str:
        self.last_node = node
        self.last_method = "visit_for_expression"
        return "for_expression"

    def visit_for_of_expression(self, node: object) -> str:
        self.last_node = node
        self.last_method = "visit_for_of_expression"
        return "for_of_expression"

    def visit_at_expression(self, node: object) -> str:
        self.last_node = node
        self.last_method = "visit_at_expression"
        return "at_expression"

    def visit_in_expression(self, node: object) -> str:
        self.last_node = node
        self.last_method = "visit_in_expression"
        return "in_expression"

    def visit_of_expression(self, node: object) -> str:
        self.last_node = node
        self.last_method = "visit_of_expression"
        return "of_expression"


class TestConditionAcceptMethods:
    """Each condition class accept() method routes to the correct visitor method."""

    def test_for_expression_accept_calls_visit_for_expression(self) -> None:
        """Line 353: ForExpression.accept delegates to visitor.visit_for_expression."""
        r = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10))
        fe = ForExpression(quantifier="all", variable="i", iterable=r, body=IntegerLiteral(value=1))
        visitor = _MinimalVisitor()
        result = fe.accept(visitor)
        assert result == "for_expression"
        assert visitor.last_node is fe
        assert visitor.last_method == "visit_for_expression"

    def test_for_of_expression_accept_calls_visit_for_of_expression(self) -> None:
        """Line 380: ForOfExpression.accept delegates to visitor.visit_for_of_expression."""
        fo = ForOfExpression(quantifier="any", string_set="them")
        visitor = _MinimalVisitor()
        result = fo.accept(visitor)
        assert result == "for_of_expression"
        assert visitor.last_node is fo
        assert visitor.last_method == "visit_for_of_expression"

    def test_at_expression_accept_calls_visit_at_expression(self) -> None:
        """Line 402: AtExpression.accept delegates to visitor.visit_at_expression."""
        ae = AtExpression(string_id="$a", offset=IntegerLiteral(value=0))
        visitor = _MinimalVisitor()
        result = ae.accept(visitor)
        assert result == "at_expression"
        assert visitor.last_node is ae
        assert visitor.last_method == "visit_at_expression"

    def test_in_expression_accept_calls_visit_in_expression(self) -> None:
        """Line 434: InExpression.accept delegates to visitor.visit_in_expression."""
        r = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10))
        ie = InExpression(subject="$a", range=r)
        visitor = _MinimalVisitor()
        result = ie.accept(visitor)
        assert result == "in_expression"
        assert visitor.last_node is ie
        assert visitor.last_method == "visit_in_expression"

    def test_of_expression_accept_calls_visit_of_expression(self) -> None:
        """Line 455: OfExpression.accept delegates to visitor.visit_of_expression."""
        oe = OfExpression(quantifier="all", string_set="them")
        visitor = _MinimalVisitor()
        result = oe.accept(visitor)
        assert result == "of_expression"
        assert visitor.last_node is oe
        assert visitor.last_method == "visit_of_expression"
