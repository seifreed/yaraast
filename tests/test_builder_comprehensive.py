"""Comprehensive tests for builder module to achieve 80%+ coverage.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

import pytest

from yaraast.ast.conditions import AtExpression, ForExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringIdentifier,
    StringLiteral,
    UnaryExpression,
)
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.expression_builder import ExpressionBuilder
from yaraast.errors import ValidationError


class TestConditionBuilderStringReferences:
    """Test string reference methods in ConditionBuilder."""

    def test_string_creates_string_identifier(self) -> None:
        """String method should create StringIdentifier."""
        builder = ConditionBuilder()

        result = builder.string("$malware")
        expr = result.build()

        assert isinstance(expr, StringIdentifier)
        assert expr.name == "$malware"

    def test_string_count_creates_string_count(self) -> None:
        """String_count should create StringCount expression."""
        builder = ConditionBuilder()

        result = builder.string_count("#malware")
        expr = result.build()

        assert expr is not None
        # StringCount contains the string_id without the # prefix
        assert hasattr(expr, "string_id")

    def test_string_offset_without_index(self) -> None:
        """String_offset without index should create offset expression."""
        builder = ConditionBuilder()

        result = builder.string_offset("@malware")
        expr = result.build()

        assert expr is not None
        assert hasattr(expr, "string_id")

    def test_string_offset_with_index(self) -> None:
        """String_offset with index should include index expression."""
        builder = ConditionBuilder()

        result = builder.string_offset("@malware", 0)
        expr = result.build()

        assert expr is not None
        assert hasattr(expr, "index")
        assert expr.index is not None

    def test_string_length_without_index(self) -> None:
        """String_length without index should create length expression."""
        builder = ConditionBuilder()

        result = builder.string_length("!malware")
        expr = result.build()

        assert expr is not None
        assert hasattr(expr, "string_id")

    def test_string_length_with_index(self) -> None:
        """String_length with index should include index expression."""
        builder = ConditionBuilder()

        result = builder.string_length("!malware", 1)
        expr = result.build()

        assert expr is not None
        assert hasattr(expr, "index")
        assert expr.index is not None


class TestConditionBuilderLiterals:
    """Test literal creation methods."""

    def test_true_creates_boolean_true(self) -> None:
        """True method should create BooleanLiteral with True value."""
        builder = ConditionBuilder()

        result = builder.true()
        expr = result.build()

        assert isinstance(expr, BooleanLiteral)
        assert expr.value is True

    def test_false_creates_boolean_false(self) -> None:
        """False method should create BooleanLiteral with False value."""
        builder = ConditionBuilder()

        result = builder.false()
        expr = result.build()

        assert isinstance(expr, BooleanLiteral)
        assert expr.value is False

    def test_integer_creates_integer_literal(self) -> None:
        """Integer method should create IntegerLiteral."""
        builder = ConditionBuilder()

        result = builder.integer(42)
        expr = result.build()

        assert isinstance(expr, IntegerLiteral)
        assert expr.value == 42

    def test_filesize_creates_filesize_identifier(self) -> None:
        """Filesize method should create filesize identifier."""
        builder = ConditionBuilder()

        result = builder.filesize()
        expr = result.build()

        assert isinstance(expr, Identifier)
        assert expr.name == "filesize"

    def test_entrypoint_creates_entrypoint_identifier(self) -> None:
        """Entrypoint method should create entrypoint identifier."""
        builder = ConditionBuilder()

        result = builder.entrypoint()
        expr = result.build()

        assert isinstance(expr, Identifier)
        assert expr.name == "entrypoint"

    def test_identifier_creates_generic_identifier(self) -> None:
        """Identifier method should create generic identifier."""
        builder = ConditionBuilder()

        result = builder.identifier("pe.number_of_sections")
        expr = result.build()

        assert isinstance(expr, Identifier)
        assert expr.name == "pe.number_of_sections"


class TestConditionBuilderRangeAndAccess:
    """Test range and access methods."""

    def test_range_with_integers(self) -> None:
        """Range method should accept integer values."""
        builder = ConditionBuilder()

        result = builder.range(0, 100)
        expr = result.build()

        assert isinstance(expr, RangeExpression)
        assert isinstance(expr.low, IntegerLiteral)
        assert expr.low.value == 0
        assert isinstance(expr.high, IntegerLiteral)
        assert expr.high.value == 100

    def test_range_with_builders(self) -> None:
        """Range method should accept ConditionBuilder objects."""
        builder = ConditionBuilder()
        start = ConditionBuilder().integer(10)
        end = ConditionBuilder().integer(50)

        result = builder.range(start, end)
        expr = result.build()

        assert isinstance(expr, RangeExpression)
        assert isinstance(expr.low, IntegerLiteral)
        assert expr.low.value == 10

    def test_member_access_with_expression(self) -> None:
        """Member_access should work with Expression objects."""
        builder = ConditionBuilder()
        obj_expr = Identifier(name="pe")

        result = builder.member_access(obj_expr, "number_of_sections")
        expr = result.build()

        assert isinstance(expr, MemberAccess)
        assert expr.member == "number_of_sections"

    def test_member_access_with_builder(self) -> None:
        """Member_access should work with ConditionBuilder."""
        builder = ConditionBuilder()
        obj = ConditionBuilder().identifier("pe")

        result = builder.member_access(obj, "timestamp")
        expr = result.build()

        assert isinstance(expr, MemberAccess)
        assert expr.member == "timestamp"

    def test_array_access_with_integer_index(self) -> None:
        """Array_access should work with integer index."""
        builder = ConditionBuilder()
        array = ConditionBuilder().identifier("pe.sections")

        result = builder.array_access(array, 0)
        expr = result.build()

        assert isinstance(expr, ArrayAccess)
        assert isinstance(expr.index, IntegerLiteral)
        assert expr.index.value == 0

    def test_array_access_with_expression_index(self) -> None:
        """Array_access should work with Expression index."""
        builder = ConditionBuilder()
        array = Identifier(name="sections")
        index = IntegerLiteral(value=2)

        result = builder.array_access(array, index)
        expr = result.build()

        assert isinstance(expr, ArrayAccess)
        assert expr.index.value == 2


class TestConditionBuilderLogicalOperators:
    """Test logical operator methods."""

    def test_and_combines_expressions(self) -> None:
        """And_ should combine two expressions with AND."""
        left = ConditionBuilder().true()
        right = ConditionBuilder().false()

        result = left.and_(right)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "and"
        assert isinstance(expr.left, BooleanLiteral)
        assert isinstance(expr.right, BooleanLiteral)

    def test_and_with_expression_object(self) -> None:
        """And_ should work with Expression objects."""
        left = ConditionBuilder().true()
        right = BooleanLiteral(value=False)

        result = left.and_(right)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "and"

    def test_and_on_empty_expression_raises_error(self) -> None:
        """And_ on empty expression should raise ValueError."""
        builder = ConditionBuilder()

        with pytest.raises(ValidationError, match="Cannot apply AND to empty expression"):
            builder.and_(ConditionBuilder().true())

    def test_or_combines_expressions(self) -> None:
        """Or_ should combine two expressions with OR."""
        left = ConditionBuilder().true()
        right = ConditionBuilder().false()

        result = left.or_(right)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "or"

    def test_or_on_empty_expression_raises_error(self) -> None:
        """Or_ on empty expression should raise ValueError."""
        builder = ConditionBuilder()

        with pytest.raises(ValidationError, match="Cannot apply OR to empty expression"):
            builder.or_(ConditionBuilder().true())

    def test_not_negates_expression(self) -> None:
        """Not_ should negate expression."""
        builder = ConditionBuilder().true()

        result = builder.not_()
        expr = result.build()

        assert isinstance(expr, UnaryExpression)
        assert expr.operator == "not"
        assert isinstance(expr.operand, BooleanLiteral)

    def test_not_on_empty_expression_raises_error(self) -> None:
        """Not_ on empty expression should raise ValueError."""
        builder = ConditionBuilder()

        with pytest.raises(ValidationError, match="Cannot apply NOT to empty expression"):
            builder.not_()


class TestConditionBuilderComparisonOperators:
    """Test comparison operator methods."""

    def test_eq_with_integer(self) -> None:
        """Eq should work with integer values."""
        left = ConditionBuilder().integer(42)

        result = left.eq(42)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "=="
        assert isinstance(expr.right, IntegerLiteral)

    def test_eq_with_string(self) -> None:
        """Eq should work with string values."""
        left = ConditionBuilder().identifier("name")

        result = left.eq("malware")
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "=="
        assert isinstance(expr.right, StringLiteral)

    def test_ne_creates_not_equal_comparison(self) -> None:
        """Ne should create != comparison."""
        left = ConditionBuilder().integer(10)

        result = left.ne(20)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "!="

    def test_lt_creates_less_than_comparison(self) -> None:
        """Lt should create < comparison."""
        left = ConditionBuilder().filesize()

        result = left.lt(1000)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "<"

    def test_le_creates_less_or_equal_comparison(self) -> None:
        """Le should create <= comparison."""
        left = ConditionBuilder().integer(5)

        result = left.le(10)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "<="

    def test_gt_creates_greater_than_comparison(self) -> None:
        """Gt should create > comparison."""
        left = ConditionBuilder().filesize()

        result = left.gt(500)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == ">"

    def test_ge_creates_greater_or_equal_comparison(self) -> None:
        """Ge should create >= comparison."""
        left = ConditionBuilder().integer(100)

        result = left.ge(50)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == ">="


class TestConditionBuilderStringOperators:
    """Test string operator methods."""

    def test_contains_with_string(self) -> None:
        """Contains should create contains comparison."""
        left = ConditionBuilder().identifier("filename")

        result = left.contains("malware")
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "contains"

    def test_matches_creates_regex_match(self) -> None:
        """Matches should create regex match operation."""
        left = ConditionBuilder().identifier("content")

        result = left.matches(r"[0-9]+")
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "matches"

    def test_startswith_creates_prefix_check(self) -> None:
        """Startswith should create prefix check."""
        left = ConditionBuilder().identifier("path")

        result = left.startswith("/tmp")
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "startswith"

    def test_endswith_creates_suffix_check(self) -> None:
        """Endswith should create suffix check."""
        left = ConditionBuilder().identifier("extension")

        result = left.endswith(".exe")
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "endswith"

    def test_icontains_creates_case_insensitive_contains(self) -> None:
        """Icontains should create case-insensitive contains."""
        left = ConditionBuilder().identifier("name")

        result = left.icontains("MALWARE")
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "icontains"

    def test_iequals_creates_case_insensitive_equals(self) -> None:
        """Iequals should create case-insensitive equals."""
        left = ConditionBuilder().identifier("type")

        result = left.iequals("TROJAN")
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "iequals"


class TestConditionBuilderSpecialConditions:
    """Test special condition methods."""

    def test_at_creates_at_expression(self) -> None:
        """At should create AtExpression for string at offset."""
        builder = ConditionBuilder().string("$mz")

        result = builder.at(0)
        expr = result.build()

        assert isinstance(expr, AtExpression)
        assert expr.string_id == "$mz"
        assert isinstance(expr.offset, IntegerLiteral)
        assert expr.offset.value == 0

    def test_at_with_builder_offset(self) -> None:
        """At should work with ConditionBuilder offset."""
        builder = ConditionBuilder().string("$pe")
        offset = ConditionBuilder().integer(100)

        result = builder.at(offset)
        expr = result.build()

        assert isinstance(expr, AtExpression)
        assert isinstance(expr.offset, IntegerLiteral)

    def test_at_on_non_string_raises_error(self) -> None:
        """At on non-string identifier should raise ValueError."""
        builder = ConditionBuilder().integer(42)

        with pytest.raises(ValidationError, match="'at' can only be used with string identifiers"):
            builder.at(0)

    def test_in_range_creates_in_expression(self) -> None:
        """In_range should create InExpression."""
        builder = ConditionBuilder().string("$signature")

        result = builder.in_range(0, 100)
        expr = result.build()

        assert isinstance(expr, InExpression)
        assert expr.subject == "$signature"
        assert isinstance(expr.range, RangeExpression)

    def test_in_range_with_builder_bounds(self) -> None:
        """In_range should work with ConditionBuilder bounds."""
        builder = ConditionBuilder().string("$pattern")
        start = ConditionBuilder().integer(10)
        end = ConditionBuilder().integer(200)

        result = builder.in_range(start, end)
        expr = result.build()

        assert isinstance(expr, InExpression)

    def test_in_range_on_non_string_raises_error(self) -> None:
        """In_range on non-string should raise ValueError."""
        builder = ConditionBuilder().filesize()

        with pytest.raises(ValidationError, match="'in' can only be used with string identifiers"):
            builder.in_range(0, 100)


class TestConditionBuilderQuantifiers:
    """Test quantifier methods."""

    def test_any_of_with_multiple_strings(self) -> None:
        """Any_of should create OfExpression with multiple strings."""
        builder = ConditionBuilder()

        result = builder.any_of("$s1", "$s2", "$s3")
        expr = result.build()

        assert isinstance(expr, OfExpression)
        assert isinstance(expr.quantifier, StringLiteral)
        assert expr.quantifier.value == "any"
        assert isinstance(expr.string_set, SetExpression)

    def test_any_of_them(self) -> None:
        """Any_of with 'them' should use them identifier."""
        builder = ConditionBuilder()

        result = builder.any_of("them")
        expr = result.build()

        assert isinstance(expr, OfExpression)
        assert isinstance(expr.string_set, Identifier)
        assert expr.string_set.name == "them"

    def test_all_of_with_multiple_strings(self) -> None:
        """All_of should create OfExpression with all quantifier."""
        builder = ConditionBuilder()

        result = builder.all_of("$a", "$b", "$c")
        expr = result.build()

        assert isinstance(expr, OfExpression)
        assert isinstance(expr.quantifier, StringLiteral)
        assert expr.quantifier.value == "all"

    def test_all_of_them(self) -> None:
        """All_of with 'them' should use them identifier."""
        builder = ConditionBuilder()

        result = builder.all_of("them")
        expr = result.build()

        assert isinstance(expr, OfExpression)
        assert isinstance(expr.string_set, Identifier)
        assert expr.string_set.name == "them"

    def test_n_of_with_count(self) -> None:
        """N_of should create OfExpression with integer quantifier."""
        builder = ConditionBuilder()

        result = builder.n_of(2, "$x", "$y", "$z")
        expr = result.build()

        assert isinstance(expr, OfExpression)
        assert isinstance(expr.quantifier, IntegerLiteral)
        assert expr.quantifier.value == 2


class TestConditionBuilderForLoops:
    """Test for loop methods."""

    def test_for_any_creates_for_expression(self) -> None:
        """For_any should create ForExpression with any quantifier."""
        builder = ConditionBuilder()
        iterable = ConditionBuilder().identifier("pe.sections")
        condition = ConditionBuilder().identifier("section.name").contains("text")

        result = builder.for_any("section", iterable, condition)
        expr = result.build()

        assert isinstance(expr, ForExpression)
        assert expr.quantifier == "any"
        assert expr.variable == "section"

    def test_for_any_with_expression_objects(self) -> None:
        """For_any should work with Expression objects."""
        builder = ConditionBuilder()
        iterable = Identifier(name="items")
        condition = BooleanLiteral(value=True)

        result = builder.for_any("item", iterable, condition)
        expr = result.build()

        assert isinstance(expr, ForExpression)
        assert expr.quantifier == "any"

    def test_for_all_creates_for_expression(self) -> None:
        """For_all should create ForExpression with all quantifier."""
        builder = ConditionBuilder()
        iterable = ConditionBuilder().range(0, 10)
        condition = ConditionBuilder().true()

        result = builder.for_all("i", iterable, condition)
        expr = result.build()

        assert isinstance(expr, ForExpression)
        assert expr.quantifier == "all"
        assert expr.variable == "i"


class TestConditionBuilderArithmeticOperators:
    """Test arithmetic operator methods."""

    def test_add_creates_addition(self) -> None:
        """Add should create + operation."""
        left = ConditionBuilder().integer(10)

        result = left.add(5)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "+"

    def test_sub_creates_subtraction(self) -> None:
        """Sub should create - operation."""
        left = ConditionBuilder().filesize()

        result = left.sub(100)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "-"

    def test_mul_creates_multiplication(self) -> None:
        """Mul should create * operation."""
        left = ConditionBuilder().integer(4)

        result = left.mul(8)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "*"

    def test_div_creates_division(self) -> None:
        """Div should create / operation."""
        left = ConditionBuilder().integer(100)

        result = left.div(10)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "/"

    def test_mod_creates_modulo(self) -> None:
        """Mod should create % operation."""
        left = ConditionBuilder().integer(17)

        result = left.mod(5)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "%"


class TestConditionBuilderBitwiseOperators:
    """Test bitwise operator methods."""

    def test_bitwise_and_creates_and_operation(self) -> None:
        """Bitwise_and should create & operation."""
        left = ConditionBuilder().integer(0xFF)

        result = left.bitwise_and(0x0F)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "&"

    def test_bitwise_or_creates_or_operation(self) -> None:
        """Bitwise_or should create | operation."""
        left = ConditionBuilder().integer(0x10)

        result = left.bitwise_or(0x20)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "|"

    def test_bitwise_xor_creates_xor_operation(self) -> None:
        """Bitwise_xor should create ^ operation."""
        left = ConditionBuilder().integer(0xAA)

        result = left.bitwise_xor(0x55)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "^"

    def test_bitwise_not_creates_negation(self) -> None:
        """Bitwise_not should create ~ operation."""
        builder = ConditionBuilder().integer(0xFF)

        result = builder.bitwise_not()
        expr = result.build()

        assert isinstance(expr, UnaryExpression)
        assert expr.operator == "~"

    def test_bitwise_not_on_empty_raises_error(self) -> None:
        """Bitwise_not on empty expression should raise ValueError."""
        builder = ConditionBuilder()

        with pytest.raises(ValidationError, match="Cannot apply bitwise NOT to empty expression"):
            builder.bitwise_not()

    def test_shift_left_creates_left_shift(self) -> None:
        """Shift_left should create << operation."""
        left = ConditionBuilder().integer(1)

        result = left.shift_left(4)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "<<"

    def test_shift_right_creates_right_shift(self) -> None:
        """Shift_right should create >> operation."""
        left = ConditionBuilder().integer(32)

        result = left.shift_right(2)
        expr = result.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == ">>"


class TestConditionBuilderGrouping:
    """Test grouping methods."""

    def test_group_wraps_in_parentheses(self) -> None:
        """Group should wrap expression in parentheses."""
        builder = ConditionBuilder().true()

        result = builder.group()
        expr = result.build()

        assert isinstance(expr, ParenthesesExpression)
        assert isinstance(expr.expression, BooleanLiteral)

    def test_group_on_empty_raises_error(self) -> None:
        """Group on empty expression should raise ValueError."""
        builder = ConditionBuilder()

        with pytest.raises(ValidationError, match="Cannot group empty expression"):
            builder.group()


class TestConditionBuilderHelperMethods:
    """Test helper methods."""

    def test_to_expression_with_builder(self) -> None:
        """_to_expression should convert ConditionBuilder to Expression."""
        builder = ConditionBuilder()
        value = ConditionBuilder().integer(42)

        expr = builder._to_expression(value)

        assert isinstance(expr, IntegerLiteral)
        assert expr.value == 42

    def test_to_expression_with_expression_object(self) -> None:
        """_to_expression should pass through Expression objects."""
        builder = ConditionBuilder()
        value = BooleanLiteral(value=True)

        expr = builder._to_expression(value)

        assert expr is value

    def test_to_expression_with_integer(self) -> None:
        """_to_expression should convert integers to IntegerLiteral."""
        builder = ConditionBuilder()

        expr = builder._to_expression(100)

        assert isinstance(expr, IntegerLiteral)
        assert expr.value == 100

    def test_to_expression_with_string_identifier(self) -> None:
        """_to_expression should convert $-prefixed strings to StringIdentifier."""
        builder = ConditionBuilder()

        expr = builder._to_expression("$malware")

        assert isinstance(expr, StringIdentifier)
        assert expr.name == "$malware"

    def test_to_expression_with_regular_string(self) -> None:
        """_to_expression should convert strings to StringLiteral."""
        builder = ConditionBuilder()

        expr = builder._to_expression("hello")

        assert isinstance(expr, StringLiteral)
        assert expr.value == "hello"

    def test_to_expression_with_empty_builder_raises_error(self) -> None:
        """_to_expression with empty builder should raise ValueError."""
        builder = ConditionBuilder()
        empty_builder = ConditionBuilder()

        with pytest.raises(ValidationError, match="Empty condition builder"):
            builder._to_expression(empty_builder)

    def test_to_expression_with_invalid_type_raises_error(self) -> None:
        """_to_expression with invalid type should raise TypeError."""
        builder = ConditionBuilder()

        with pytest.raises(TypeError, match="Cannot convert .* to expression"):
            builder._to_expression([1, 2, 3])  # type: ignore

    def test_build_on_empty_raises_error(self) -> None:
        """Build on empty expression should raise ValueError."""
        builder = ConditionBuilder()

        with pytest.raises(ValidationError, match="Cannot build empty expression"):
            builder.build()


class TestConditionBuilderStaticMethods:
    """Test static factory methods."""

    def test_match_creates_string_identifier(self) -> None:
        """Match static method should create string identifier."""
        builder = ConditionBuilder.match("$pattern")
        expr = builder.build()

        assert isinstance(expr, StringIdentifier)
        assert expr.name == "$pattern"

    def test_them_creates_them_identifier(self) -> None:
        """Them static method should create them identifier."""
        builder = ConditionBuilder.them()
        expr = builder.build()

        assert isinstance(expr, Identifier)
        assert expr.name == "them"


class TestExpressionBuilder:
    """Test ExpressionBuilder static utility methods."""

    def test_string_creates_string_identifier(self) -> None:
        """String method should create StringIdentifier."""
        expr = ExpressionBuilder.string("$test")

        assert isinstance(expr, StringIdentifier)
        assert expr.name == "$test"

    def test_integer_creates_integer_literal(self) -> None:
        """Integer method should create IntegerLiteral."""
        expr = ExpressionBuilder.integer(100)

        assert isinstance(expr, IntegerLiteral)
        assert expr.value == 100

    def test_double_creates_double_literal(self) -> None:
        """Double method should create DoubleLiteral."""
        expr = ExpressionBuilder.double(3.14)

        assert isinstance(expr, DoubleLiteral)
        assert expr.value == 3.14

    def test_string_literal_creates_string_literal(self) -> None:
        """String_literal method should create StringLiteral."""
        expr = ExpressionBuilder.string_literal("hello")

        assert isinstance(expr, StringLiteral)
        assert expr.value == "hello"

    def test_true_creates_boolean_true(self) -> None:
        """True method should create BooleanLiteral with True."""
        expr = ExpressionBuilder.true()

        assert isinstance(expr, BooleanLiteral)
        assert expr.value is True

    def test_false_creates_boolean_false(self) -> None:
        """False method should create BooleanLiteral with False."""
        expr = ExpressionBuilder.false()

        assert isinstance(expr, BooleanLiteral)
        assert expr.value is False

    def test_identifier_creates_identifier(self) -> None:
        """Identifier method should create Identifier."""
        expr = ExpressionBuilder.identifier("pe.sections")

        assert isinstance(expr, Identifier)
        assert expr.name == "pe.sections"

    def test_filesize_creates_filesize_identifier(self) -> None:
        """Filesize method should create filesize identifier."""
        expr = ExpressionBuilder.filesize()

        assert isinstance(expr, Identifier)
        assert expr.name == "filesize"

    def test_entrypoint_creates_entrypoint_identifier(self) -> None:
        """Entrypoint method should create entrypoint identifier."""
        expr = ExpressionBuilder.entrypoint()

        assert isinstance(expr, Identifier)
        assert expr.name == "entrypoint"

    def test_them_creates_them_identifier(self) -> None:
        """Them method should create them identifier."""
        expr = ExpressionBuilder.them()

        assert isinstance(expr, Identifier)
        assert expr.name == "them"

    def test_range_with_integers(self) -> None:
        """Range method should accept integer values."""
        expr = ExpressionBuilder.range(0, 100)

        assert isinstance(expr, RangeExpression)
        assert isinstance(expr.low, IntegerLiteral)
        assert expr.low.value == 0
        assert isinstance(expr.high, IntegerLiteral)
        assert expr.high.value == 100

    def test_range_with_expressions(self) -> None:
        """Range method should accept Expression objects."""
        low = IntegerLiteral(value=10)
        high = IntegerLiteral(value=50)

        expr = ExpressionBuilder.range(low, high)

        assert isinstance(expr, RangeExpression)
        assert expr.low is low
        assert expr.high is high

    def test_set_creates_set_expression(self) -> None:
        """Set method should create SetExpression."""
        elem1 = StringIdentifier(name="$a")
        elem2 = StringIdentifier(name="$b")

        expr = ExpressionBuilder.set(elem1, elem2)

        assert isinstance(expr, SetExpression)
        assert len(expr.elements) == 2

    def test_string_set_creates_string_set(self) -> None:
        """String_set method should create set of StringIdentifiers."""
        expr = ExpressionBuilder.string_set("$x", "$y", "$z")

        assert isinstance(expr, SetExpression)
        assert len(expr.elements) == 3
        assert all(isinstance(e, StringIdentifier) for e in expr.elements)

    def test_any_of_them_creates_of_expression(self) -> None:
        """Any_of_them should create 'any of them' expression."""
        expr = ExpressionBuilder.any_of_them()

        assert isinstance(expr, OfExpression)
        assert isinstance(expr.quantifier, StringLiteral)
        assert expr.quantifier.value == "any"
        assert isinstance(expr.string_set, Identifier)
        assert expr.string_set.name == "them"

    def test_all_of_them_creates_of_expression(self) -> None:
        """All_of_them should create 'all of them' expression."""
        expr = ExpressionBuilder.all_of_them()

        assert isinstance(expr, OfExpression)
        assert isinstance(expr.quantifier, StringLiteral)
        assert expr.quantifier.value == "all"

    def test_any_of_creates_of_expression(self) -> None:
        """Any_of should create 'any of' expression with strings."""
        expr = ExpressionBuilder.any_of("$a", "$b", "$c")

        assert isinstance(expr, OfExpression)
        assert isinstance(expr.string_set, SetExpression)

    def test_all_of_creates_of_expression(self) -> None:
        """All_of should create 'all of' expression with strings."""
        expr = ExpressionBuilder.all_of("$x", "$y")

        assert isinstance(expr, OfExpression)
        assert expr.quantifier.value == "all"

    def test_n_of_creates_of_expression(self) -> None:
        """N_of should create 'n of' expression."""
        expr = ExpressionBuilder.n_of(2, "$p1", "$p2", "$p3")

        assert isinstance(expr, OfExpression)
        assert isinstance(expr.quantifier, IntegerLiteral)
        assert expr.quantifier.value == 2

    def test_and_with_multiple_expressions(self) -> None:
        """And_ should chain multiple expressions."""
        e1 = BooleanLiteral(value=True)
        e2 = BooleanLiteral(value=False)
        e3 = BooleanLiteral(value=True)

        expr = ExpressionBuilder.and_(e1, e2, e3)

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "and"

    def test_and_with_single_expression(self) -> None:
        """And_ with single expression should return that expression."""
        e1 = BooleanLiteral(value=True)

        expr = ExpressionBuilder.and_(e1)

        assert expr is e1

    def test_and_with_no_expressions_raises_error(self) -> None:
        """And_ with no expressions should raise ValueError."""
        with pytest.raises(ValidationError, match="At least one expression required"):
            ExpressionBuilder.and_()

    def test_or_with_multiple_expressions(self) -> None:
        """Or_ should chain multiple expressions."""
        e1 = BooleanLiteral(value=True)
        e2 = BooleanLiteral(value=False)

        expr = ExpressionBuilder.or_(e1, e2)

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "or"

    def test_or_with_no_expressions_raises_error(self) -> None:
        """Or_ with no expressions should raise ValueError."""
        with pytest.raises(ValidationError, match="At least one expression required"):
            ExpressionBuilder.or_()

    def test_not_creates_unary_expression(self) -> None:
        """Not_ should create NOT expression."""
        operand = BooleanLiteral(value=True)

        expr = ExpressionBuilder.not_(operand)

        assert isinstance(expr, UnaryExpression)
        assert expr.operator == "not"
        assert expr.operand is operand

    def test_parentheses_wraps_expression(self) -> None:
        """Parentheses should wrap expression."""
        inner = BooleanLiteral(value=True)

        expr = ExpressionBuilder.parentheses(inner)

        assert isinstance(expr, ParenthesesExpression)
        assert expr.expression is inner

    def test_at_with_integer_offset(self) -> None:
        """At should create AtExpression with integer offset."""
        expr = ExpressionBuilder.at("$mz", 0)

        assert isinstance(expr, AtExpression)
        assert expr.string_id == "$mz"
        assert isinstance(expr.offset, IntegerLiteral)
        assert expr.offset.value == 0

    def test_at_with_expression_offset(self) -> None:
        """At should accept Expression offset."""
        offset = IntegerLiteral(value=100)

        expr = ExpressionBuilder.at("$pe", offset)

        assert isinstance(expr, AtExpression)
        assert expr.offset is offset

    def test_in_creates_in_expression(self) -> None:
        """In_ should create InExpression."""
        expr = ExpressionBuilder.in_("$sig", 0, 100)

        assert isinstance(expr, InExpression)
        assert expr.subject == "$sig"
        assert isinstance(expr.range, RangeExpression)

    def test_for_any_creates_for_expression(self) -> None:
        """For_any should create ForExpression."""
        iterable = Identifier(name="sections")
        body = BooleanLiteral(value=True)

        expr = ExpressionBuilder.for_any("s", iterable, body)

        assert isinstance(expr, ForExpression)
        assert expr.quantifier == "any"
        assert expr.variable == "s"

    def test_for_all_creates_for_expression(self) -> None:
        """For_all should create ForExpression."""
        iterable = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10))
        body = BooleanLiteral(value=True)

        expr = ExpressionBuilder.for_all("i", iterable, body)

        assert isinstance(expr, ForExpression)
        assert expr.quantifier == "all"

    def test_function_call_creates_function_call(self) -> None:
        """Function_call should create FunctionCall."""
        arg1 = IntegerLiteral(value=100)
        arg2 = StringLiteral(value="test")

        expr = ExpressionBuilder.function_call("hash.md5", arg1, arg2)

        assert isinstance(expr, FunctionCall)
        assert expr.function == "hash.md5"
        assert len(expr.arguments) == 2

    def test_member_access_creates_member_access(self) -> None:
        """Member_access should create MemberAccess."""
        obj = Identifier(name="pe")

        expr = ExpressionBuilder.member_access(obj, "timestamp")

        assert isinstance(expr, MemberAccess)
        assert expr.object is obj
        assert expr.member == "timestamp"

    def test_array_access_with_integer_index(self) -> None:
        """Array_access should work with integer index."""
        array = Identifier(name="sections")

        expr = ExpressionBuilder.array_access(array, 0)

        assert isinstance(expr, ArrayAccess)
        assert isinstance(expr.index, IntegerLiteral)
        assert expr.index.value == 0

    def test_array_access_with_expression_index(self) -> None:
        """Array_access should work with Expression index."""
        array = Identifier(name="items")
        index = IntegerLiteral(value=5)

        expr = ExpressionBuilder.array_access(array, index)

        assert isinstance(expr, ArrayAccess)
        assert expr.index is index


class TestConditionBuilderComplexScenarios:
    """Test complex real-world condition building scenarios."""

    def test_filesize_check_with_comparison(self) -> None:
        """Build filesize < 1MB condition."""
        condition = ConditionBuilder().filesize().lt(1048576)
        expr = condition.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "<"

    def test_string_at_entrypoint(self) -> None:
        """Build $string at entrypoint condition."""
        condition = ConditionBuilder().string("$mz").at(ConditionBuilder().entrypoint())
        expr = condition.build()

        assert isinstance(expr, AtExpression)

    def test_complex_logical_expression(self) -> None:
        """Build (true and false) or true condition."""
        condition = (
            ConditionBuilder()
            .true()
            .and_(ConditionBuilder().false())
            .group()
            .or_(ConditionBuilder().true())
        )
        expr = condition.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "or"

    def test_for_loop_with_range(self) -> None:
        """Build for all i in (0..10) condition."""
        builder = ConditionBuilder()
        iterable = builder.range(0, 10)
        body = ConditionBuilder().identifier("i").lt(5)

        condition = builder.for_all("i", iterable, body)
        expr = condition.build()

        assert isinstance(expr, ForExpression)
        assert expr.quantifier == "all"

    def test_arithmetic_expression_chain(self) -> None:
        """Build complex arithmetic: (x + 5) * 2 - 10."""
        condition = ConditionBuilder().identifier("x").add(5).group().mul(2).sub(10)
        expr = condition.build()

        assert isinstance(expr, BinaryExpression)

    def test_bitwise_operations_chain(self) -> None:
        """Build bitwise expression: (x & 0xFF) | 0x80."""
        condition = ConditionBuilder().identifier("x").bitwise_and(0xFF).group().bitwise_or(0x80)
        expr = condition.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == "|"

    def test_string_count_comparison(self) -> None:
        """Build #malware > 5 condition."""
        condition = ConditionBuilder().string_count("#malware").gt(5)
        expr = condition.build()

        assert isinstance(expr, BinaryExpression)
        assert expr.operator == ">"

    def test_member_array_access_chain(self) -> None:
        """Build pe.sections[0].name condition."""
        obj = ConditionBuilder().identifier("pe")
        sections = ConditionBuilder().member_access(obj, "sections")
        section = ConditionBuilder().array_access(sections, 0)
        condition = ConditionBuilder().member_access(section, "name")

        expr = condition.build()

        assert isinstance(expr, MemberAccess)
        assert expr.member == "name"
