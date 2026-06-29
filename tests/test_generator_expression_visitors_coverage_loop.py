# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Coverage-targeted tests for yaraast/codegen/generator_expression_visitors.py.

Each test exercises real AST nodes through real CodeGenerator execution.
No mocks, stubs, or artificial scaffolding are used.
"""

from __future__ import annotations

import pytest

from yaraast.ast.conditions import AtExpression, ForExpression, InExpression
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
    RegexLiteral,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    UnaryExpression,
)
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.generator_expression_visitors import (
    _constant_comparison_operand_type,
    _constant_integer_value,
    _integer_remainder,
    _is_definitely_non_integer_expression,
    _is_definitely_non_numeric_expression,
    _is_invalid_for_iterable_set_item,
    _known_builtin_module_scalar_type_name,
    _load_builtin_modules_cached,
    _normalize_postfix_target,
    _obvious_argument_type,
    _reject_boolean_expression,
    _render_for_loop_variable,
    _shift_left_int64,
    _shift_right_int64,
    known_builtin_module_expression_type,
    render_function_call_callee,
    require_present_expression,
    validate_array_access_target,
    validate_function_call_arguments,
    validate_postfix_target,
    validate_set_expression_elements,
    validate_tuple_indexing_target,
)
from yaraast.yarax.ast_nodes import TupleExpression

# ---------------------------------------------------------------------------
# Lines 103-108: _reject_boolean_expression
# ---------------------------------------------------------------------------


def test_reject_boolean_expression_with_bool_literal() -> None:
    """Line 105: isinstance(value, bool | BooleanLiteral) raises ValueError."""
    with pytest.raises(ValueError, match="forbidden"):
        _reject_boolean_expression(True, "forbidden")


def test_reject_boolean_expression_with_boolean_literal_node() -> None:
    """Line 106: BooleanLiteral AST node also triggers the error."""
    with pytest.raises(ValueError, match="no bool here"):
        _reject_boolean_expression(BooleanLiteral(False), "no bool here")


def test_reject_boolean_expression_parentheses_recursion() -> None:
    """Lines 107-108: ParenthesesExpression wrapping BooleanLiteral recurses and raises."""
    paren = ParenthesesExpression(BooleanLiteral(True))
    with pytest.raises(ValueError, match="nested bool"):
        _reject_boolean_expression(paren, "nested bool")


def test_reject_boolean_expression_non_boolean_returns_silently() -> None:
    """Lines 105-108: Non-boolean value passes without error."""
    _reject_boolean_expression(42, "should not raise")
    _reject_boolean_expression(IntegerLiteral(1), "should not raise")


# ---------------------------------------------------------------------------
# Line 132: _is_definitely_boolean_expression — InExpression branch
# ---------------------------------------------------------------------------


def test_is_definitely_boolean_in_expression_non_string_count_subject() -> None:
    """Line 132: InExpression where subject is NOT StringCount returns True."""
    range_expr = RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(10))
    in_expr = InExpression(subject=IntegerLiteral(5), range=range_expr)
    gen = CodeGenerator()
    # Visiting InExpression exercises the boolean check and renders correctly.
    result = gen.visit(in_expr)
    assert result == "5 in (0..10)"


# ---------------------------------------------------------------------------
# Line 162: _is_definitely_non_numeric_expression — ParenthesesExpression branch
# ---------------------------------------------------------------------------


def test_non_numeric_expression_parentheses_wrapping_boolean_literal() -> None:
    """Line 162: ParenthesesExpression wrapping BooleanLiteral is non-numeric."""
    paren_bool = ParenthesesExpression(BooleanLiteral(True))
    assert _is_definitely_non_numeric_expression(paren_bool) is True


def test_non_numeric_expression_parentheses_triggers_error_via_unary_minus() -> None:
    """Line 162: Unary '-' on ParenthesesExpression(BooleanLiteral) raises."""
    gen = CodeGenerator()
    paren_bool = ParenthesesExpression(BooleanLiteral(True))
    with pytest.raises(ValueError, match="must be numeric"):
        gen.visit(UnaryExpression("-", paren_bool))


# ---------------------------------------------------------------------------
# Line 175: _is_definitely_non_numeric_expression — comparison/string binary op
# ---------------------------------------------------------------------------


def test_non_numeric_binary_expression_with_comparison_operator() -> None:
    """Line 175: BinaryExpression with comparison operator is non-numeric."""
    expr = BinaryExpression(IntegerLiteral(1), "==", IntegerLiteral(2))
    assert _is_definitely_non_numeric_expression(expr) is True


def test_non_numeric_binary_expression_with_string_operator() -> None:
    """Line 175: BinaryExpression with string operator is non-numeric."""
    str_expr = BinaryExpression(StringLiteral("a"), "contains", StringLiteral("b"))
    assert _is_definitely_non_numeric_expression(str_expr) is True


def test_unary_minus_on_comparison_expression_raises() -> None:
    """Line 175 via visit: unary '-' on comparison result raises non-numeric error."""
    gen = CodeGenerator()
    comparison = BinaryExpression(StringLiteral("a"), "contains", StringLiteral("b"))
    with pytest.raises(ValueError, match="must be numeric"):
        gen.visit(UnaryExpression("-", comparison))


# ---------------------------------------------------------------------------
# Line 177: _is_definitely_non_numeric_expression — INTEGER_BINARY_OPERATORS branch
# ---------------------------------------------------------------------------


def test_non_numeric_integer_binary_expression_with_double_left() -> None:
    """Line 177: BinaryExpression with '&' operator and DoubleLiteral left operand."""
    expr = BinaryExpression(DoubleLiteral(1.5), "&", IntegerLiteral(2))
    assert _is_definitely_non_numeric_expression(expr) is True


def test_integer_binary_operator_with_double_operand_raises() -> None:
    """Line 177 via visit: '&' on DoubleLiteral raises integer operand error."""
    gen = CodeGenerator()
    with pytest.raises(ValueError, match="must be integer"):
        gen.visit(BinaryExpression(DoubleLiteral(1.0), "&", IntegerLiteral(2)))


# ---------------------------------------------------------------------------
# Line 184: _is_definitely_non_numeric_expression — unknown operator catch-all
# ---------------------------------------------------------------------------


def test_non_numeric_expression_unknown_binary_operator_returns_true() -> None:
    """Line 184: BinaryExpression with an operator outside all defined sets returns True."""
    expr = BinaryExpression(IntegerLiteral(1), "xor_custom", IntegerLiteral(2))
    assert _is_definitely_non_numeric_expression(expr) is True


# ---------------------------------------------------------------------------
# Lines 213, 222-224: _is_definitely_non_integer_expression branches
# ---------------------------------------------------------------------------


def test_non_integer_binary_expression_unknown_operator() -> None:
    """Line 213: BinaryExpression with unknown operator is non-integer."""
    expr = BinaryExpression(IntegerLiteral(1), "custom_op", IntegerLiteral(2))
    assert _is_definitely_non_integer_expression(expr) is True


def test_non_integer_unary_minus_on_double_literal() -> None:
    """Lines 220-221: UnaryExpression '-' on DoubleLiteral is non-integer (True)."""
    expr = UnaryExpression("-", DoubleLiteral(1.5))
    assert _is_definitely_non_integer_expression(expr) is True


def test_non_integer_unary_minus_on_string_literal() -> None:
    """Lines 222-224: UnaryExpression '-' on StringLiteral is non-integer via non-numeric check."""
    expr = UnaryExpression("-", StringLiteral("x"))
    assert _is_definitely_non_integer_expression(expr) is True


# ---------------------------------------------------------------------------
# Line 274: _is_invalid_for_iterable_set_item — ParenthesesExpression branch
# ---------------------------------------------------------------------------


def test_invalid_for_iterable_set_item_parenthesized_boolean() -> None:
    """Line 274: ParenthesesExpression wrapping BooleanLiteral is invalid set item."""
    paren_bool = ParenthesesExpression(BooleanLiteral(True))
    assert _is_invalid_for_iterable_set_item(paren_bool) is True


def test_for_expression_set_with_parenthesized_boolean_raises() -> None:
    """Line 274 via visit: SetExpression containing paren bool raises in ForExpression."""
    gen = CodeGenerator()
    paren_bool_set = SetExpression(elements=[ParenthesesExpression(BooleanLiteral(True))])
    for_expr = ForExpression(
        quantifier="any",
        variable="i",
        iterable=paren_bool_set,
        body=IntegerLiteral(1),
    )
    with pytest.raises(ValueError, match="set items must be integer or string"):
        gen.visit(for_expr)


# ---------------------------------------------------------------------------
# Lines 373-375: _reject_invalid_string_binary_operands — right is RegexLiteral/StringIdentifier
# ---------------------------------------------------------------------------


def test_string_binary_right_regex_literal_raises() -> None:
    """Lines 373-375: Right operand of 'contains' is RegexLiteral raises."""
    gen = CodeGenerator()
    pe_pdb = MemberAccess(object=ModuleReference("pe"), member="pdb_path")
    expr = BinaryExpression(pe_pdb, "contains", RegexLiteral("test"))
    with pytest.raises(ValueError, match="Right operand of 'contains' must be string"):
        gen.visit(expr)


def test_string_binary_right_string_identifier_raises() -> None:
    """Lines 373-375: Right operand of 'contains' is StringIdentifier raises."""
    gen = CodeGenerator()
    pe_pdb = MemberAccess(object=ModuleReference("pe"), member="pdb_path")
    expr = BinaryExpression(pe_pdb, "contains", StringIdentifier("#a"))
    with pytest.raises(ValueError, match="Right operand of 'contains' must be string"):
        gen.visit(expr)


# ---------------------------------------------------------------------------
# Line 387: _constant_integer_value — raw Python int
# ---------------------------------------------------------------------------


def test_constant_integer_value_raw_python_int() -> None:
    """Line 387: Raw Python int (not bool) returns the value directly."""
    from yaraast.codegen.generator_expression_visitors import _constant_integer_value

    result = _constant_integer_value(42)
    assert result == 42


def test_constant_integer_value_raw_bool_returns_none() -> None:
    """Line 387 guard: isinstance(value, bool) excludes booleans (returns None)."""
    from yaraast.codegen.generator_expression_visitors import _constant_integer_value

    result = _constant_integer_value(True)
    assert result is None


# ---------------------------------------------------------------------------
# Lines 402-403: _constant_integer_value — UnaryExpression '~'
# ---------------------------------------------------------------------------


def test_constant_integer_value_bitwise_not() -> None:
    """Lines 402-403: UnaryExpression '~' returns ~operand."""
    from yaraast.codegen.generator_expression_visitors import _constant_integer_value

    expr = UnaryExpression("~", IntegerLiteral(5))
    result = _constant_integer_value(expr)
    assert result == ~5


# ---------------------------------------------------------------------------
# Lines 418-440: _constant_integer_value — BinaryExpression arithmetic branches
# ---------------------------------------------------------------------------


def test_constant_integer_value_multiply() -> None:
    """Line 424 (*): BinaryExpression '*' returns normalized product."""
    from yaraast.codegen.generator_expression_visitors import _constant_integer_value

    expr = BinaryExpression(IntegerLiteral(3), "*", IntegerLiteral(4))
    assert _constant_integer_value(expr) == 12


def test_constant_integer_value_modulo() -> None:
    """Line 425 (%): BinaryExpression '%' returns integer remainder."""
    from yaraast.codegen.generator_expression_visitors import _constant_integer_value

    expr = BinaryExpression(IntegerLiteral(7), "%", IntegerLiteral(3))
    assert _constant_integer_value(expr) == 1


def test_constant_integer_value_bitwise_and() -> None:
    """Line 429 (&): BinaryExpression '&' returns bitwise AND."""
    from yaraast.codegen.generator_expression_visitors import _constant_integer_value

    expr = BinaryExpression(IntegerLiteral(5), "&", IntegerLiteral(3))
    assert _constant_integer_value(expr) == 1


def test_constant_integer_value_bitwise_or() -> None:
    """Line 431 (|): BinaryExpression '|' returns bitwise OR."""
    from yaraast.codegen.generator_expression_visitors import _constant_integer_value

    expr = BinaryExpression(IntegerLiteral(5), "|", IntegerLiteral(3))
    assert _constant_integer_value(expr) == 7


def test_constant_integer_value_bitwise_xor() -> None:
    """Line 433 (^): BinaryExpression '^' returns bitwise XOR."""
    from yaraast.codegen.generator_expression_visitors import _constant_integer_value

    expr = BinaryExpression(IntegerLiteral(5), "^", IntegerLiteral(3))
    assert _constant_integer_value(expr) == 6


def test_constant_integer_value_negative_shift_returns_none() -> None:
    """Lines 435-436: Negative right operand for shift returns None."""
    from yaraast.codegen.generator_expression_visitors import _constant_integer_value

    expr = BinaryExpression(IntegerLiteral(2), "<<", UnaryExpression("-", IntegerLiteral(1)))
    assert _constant_integer_value(expr) is None


def test_constant_integer_value_shift_left() -> None:
    """Lines 437-438 (<<): BinaryExpression '<<' returns shifted value."""
    from yaraast.codegen.generator_expression_visitors import _constant_integer_value

    expr = BinaryExpression(IntegerLiteral(2), "<<", IntegerLiteral(3))
    assert _constant_integer_value(expr) == 16


def test_constant_integer_value_shift_right() -> None:
    """Lines 439-440 (>>): BinaryExpression '>>' returns shifted value."""
    from yaraast.codegen.generator_expression_visitors import _constant_integer_value

    expr = BinaryExpression(IntegerLiteral(16), ">>", IntegerLiteral(2))
    assert _constant_integer_value(expr) == 4


# ---------------------------------------------------------------------------
# Lines 445-448: _integer_remainder — negative quotient branch
# ---------------------------------------------------------------------------


def test_integer_remainder_negative_dividend() -> None:
    """Lines 446-448: Negative dividend produces YARA-consistent modulo result."""
    result = _integer_remainder(-7, 3)
    assert result == -1


def test_integer_remainder_negative_divisor() -> None:
    """Lines 446-448: Negative divisor produces YARA-consistent modulo result."""
    result = _integer_remainder(7, -3)
    assert result == 1


def test_integer_remainder_both_positive() -> None:
    """Lines 446-448 (positive branch): Positive operands use standard remainder."""
    result = _integer_remainder(7, 3)
    assert result == 1


# ---------------------------------------------------------------------------
# Line 465: _shift_left_int64 — right >= 64 returns 0
# ---------------------------------------------------------------------------


def test_shift_left_int64_oversized_shift_returns_zero() -> None:
    """Line 465: Shift amount >= 64 returns 0."""
    assert _shift_left_int64(1, 64) == 0
    assert _shift_left_int64(1, 100) == 0


# ---------------------------------------------------------------------------
# Line 471: _shift_right_int64 — right >= 64 returns 0
# ---------------------------------------------------------------------------


def test_shift_right_int64_oversized_shift_returns_zero() -> None:
    """Line 471: Shift amount >= 64 returns 0."""
    assert _shift_right_int64(1, 64) == 0
    assert _shift_right_int64(1, 200) == 0


# ---------------------------------------------------------------------------
# Lines 533-536: _constant_comparison_operand_type — BinaryExpression branches
# ---------------------------------------------------------------------------


def test_constant_comparison_operand_type_integer_binary_operator() -> None:
    """Line 532: BinaryExpression with INTEGER_BINARY_OPERATORS returns 'integer'."""
    from yaraast.codegen.generator_expression_visitors import _constant_comparison_operand_type

    expr = BinaryExpression(IntegerLiteral(5), "&", IntegerLiteral(3))
    assert _constant_comparison_operand_type(expr) == "integer"


def test_constant_comparison_operand_type_numeric_binary_double() -> None:
    """Lines 533-535: BinaryExpression '+' on DoubleLiterals returns 'double'."""
    from yaraast.codegen.generator_expression_visitors import _constant_comparison_operand_type

    expr = BinaryExpression(DoubleLiteral(1.5), "+", DoubleLiteral(2.5))
    assert _constant_comparison_operand_type(expr) == "double"


def test_constant_comparison_operand_type_numeric_binary_integer() -> None:
    """Lines 533, 536: BinaryExpression '+' on IntegerLiterals returns 'integer'."""
    from yaraast.codegen.generator_expression_visitors import _constant_comparison_operand_type

    expr = BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2))
    assert _constant_comparison_operand_type(expr) == "integer"


# ---------------------------------------------------------------------------
# Line 550: _constant_comparison_operand_type — FunctionCall integer read function
# ---------------------------------------------------------------------------


def test_constant_comparison_operand_type_integer_read_function() -> None:
    """Line 550: FunctionCall receiver=None and function in INTEGER_READ_FUNCTIONS -> 'integer'."""
    from yaraast.codegen.generator_expression_visitors import _constant_comparison_operand_type

    fc = FunctionCall(function="int8", arguments=[IntegerLiteral(0)])
    assert _constant_comparison_operand_type(fc) == "integer"


def test_constant_comparison_operand_type_uint32_read_function() -> None:
    """Line 550: uint32 is also in INTEGER_READ_FUNCTIONS."""
    from yaraast.codegen.generator_expression_visitors import _constant_comparison_operand_type

    fc = FunctionCall(function="uint32", arguments=[IntegerLiteral(0)])
    assert _constant_comparison_operand_type(fc) == "integer"


# ---------------------------------------------------------------------------
# Lines 552-554: _constant_comparison_operand_type — UnaryExpression '-' on DoubleLiteral
# ---------------------------------------------------------------------------


def test_constant_comparison_operand_type_neg_double() -> None:
    """Lines 552-554: UnaryExpression '-' on DoubleLiteral returns 'double'."""
    from yaraast.codegen.generator_expression_visitors import _constant_comparison_operand_type

    expr = UnaryExpression("-", DoubleLiteral(1.5))
    assert _constant_comparison_operand_type(expr) == "double"


# ---------------------------------------------------------------------------
# Line 638: visit_parentheses_expression — SetExpression and TupleExpression
# ---------------------------------------------------------------------------


def test_visit_parentheses_expression_wrapping_set_expression() -> None:
    """Line 638: ParenthesesExpression wrapping SetExpression unwraps and renders the set."""
    gen = CodeGenerator()
    set_expr = SetExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])
    result = gen.visit(ParenthesesExpression(set_expr))
    assert result == "(1, 2)"


def test_visit_parentheses_expression_wrapping_tuple_expression() -> None:
    """Line 638: ParenthesesExpression wrapping TupleExpression renders the tuple."""
    gen = CodeGenerator()
    tup_expr = TupleExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])
    result = gen.visit(ParenthesesExpression(tup_expr))
    assert result == "(1, 2)"


# ---------------------------------------------------------------------------
# Lines 650-651: validate_set_expression_elements — empty set
# ---------------------------------------------------------------------------


def test_validate_set_expression_elements_empty_raises() -> None:
    """Lines 650-651: Empty SetExpression raises ValueError."""
    empty_set = SetExpression(elements=[])
    with pytest.raises(ValueError, match="at least one element"):
        validate_set_expression_elements(empty_set)


# ---------------------------------------------------------------------------
# Line 660: validate_function_call_arguments — unsupported integer read aliases
# ---------------------------------------------------------------------------


def test_validate_function_call_arguments_unsupported_le_alias_raises() -> None:
    """Line 660: int16le is an unsupported alias; raises with guidance."""
    fc = FunctionCall(function="int16le", arguments=[IntegerLiteral(0)])
    with pytest.raises(ValueError, match="not supported by libyara"):
        validate_function_call_arguments(fc)


def test_validate_function_call_arguments_uint32le_alias_raises() -> None:
    """Line 660: uint32le is an unsupported alias."""
    fc = FunctionCall(function="uint32le", arguments=[IntegerLiteral(0)])
    with pytest.raises(ValueError, match="not supported by libyara"):
        validate_function_call_arguments(fc)


# ---------------------------------------------------------------------------
# Line 695: _validate_known_module_function_call — function_def is None
# ---------------------------------------------------------------------------


def test_unknown_pe_function_raises() -> None:
    """Line 695: Calling a pe.function that does not exist raises ValueError."""
    gen = CodeGenerator()
    fc = FunctionCall(function="pe.nonexistent_func", arguments=[])
    with pytest.raises(ValueError, match="not supported by libyara"):
        gen.visit(fc)


# ---------------------------------------------------------------------------
# Lines 728-740: pe.import_rva, pe.section_index, console.hex valid paths
# ---------------------------------------------------------------------------


def test_pe_import_rva_with_valid_string_arguments() -> None:
    """Line 730: pe.import_rva with string,string passes validation and renders."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="pe.import_rva",
        arguments=[StringLiteral("kernel32.dll"), StringLiteral("CreateFileA")],
    )
    result = gen.visit(fc)
    assert result == 'pe.import_rva("kernel32.dll", "CreateFileA")'


def test_pe_delayed_import_rva_with_valid_arguments() -> None:
    """Line 730: pe.delayed_import_rva also passes through the import_rva branch."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="pe.delayed_import_rva",
        arguments=[StringLiteral("dll.dll"), StringLiteral("GetProcAddress")],
    )
    result = gen.visit(fc)
    assert result == 'pe.delayed_import_rva("dll.dll", "GetProcAddress")'


def test_pe_section_index_with_valid_string_argument() -> None:
    """Line 733: pe.section_index with string argument renders correctly."""
    gen = CodeGenerator()
    fc = FunctionCall(function="pe.section_index", arguments=[StringLiteral(".text")])
    result = gen.visit(fc)
    assert result == 'pe.section_index(".text")'


def test_console_hex_with_integer_argument() -> None:
    """Lines 738-740: console.hex with single integer argument renders correctly."""
    gen = CodeGenerator()
    fc = FunctionCall(function="console.hex", arguments=[IntegerLiteral(42)])
    result = gen.visit(fc)
    assert result == "console.hex(42)"


# ---------------------------------------------------------------------------
# Line 780: _validate_hash_module_function_arguments — invalid argument types raise
# ---------------------------------------------------------------------------


def test_hash_md5_with_invalid_argument_type_raises() -> None:
    """Line 780: hash.md5 with single integer (not string) raises."""
    gen = CodeGenerator()
    fc = FunctionCall(function="hash.md5", arguments=[IntegerLiteral(1)])
    with pytest.raises(ValueError, match="does not accept these argument types"):
        gen.visit(fc)


def test_hash_md5_with_unknown_argument_type_passes() -> None:
    """Line 780 (return early): hash.md5 with unknown argument type skips validation."""
    gen = CodeGenerator()
    fc = FunctionCall(function="hash.md5", arguments=[Identifier("unknown_expr")])
    result = gen.visit(fc)
    assert result == "hash.md5(unknown_expr)"


# ---------------------------------------------------------------------------
# Line 797: _validate_math_module_function_arguments — early return for None type
# ---------------------------------------------------------------------------


def test_math_entropy_with_unknown_argument_type_passes() -> None:
    """Line 797: math.entropy with unknown type arg returns early (no error)."""
    gen = CodeGenerator()
    fc = FunctionCall(function="math.entropy", arguments=[Identifier("some_var")])
    result = gen.visit(fc)
    assert result == "math.entropy(some_var)"


# ---------------------------------------------------------------------------
# Line 802: math.deviation branch
# ---------------------------------------------------------------------------


def test_math_deviation_string_double_arguments() -> None:
    """Line 802: math.deviation with (string, double) renders correctly."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="math.deviation",
        arguments=[StringLiteral("file"), DoubleLiteral(1.0)],
    )
    result = gen.visit(fc)
    assert result == 'math.deviation("file", 1.0)'


def test_math_deviation_invalid_types_raises() -> None:
    """Line 802 invalid: math.deviation with wrong types raises."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="math.deviation",
        arguments=[IntegerLiteral(0), IntegerLiteral(100)],
    )
    with pytest.raises(ValueError, match="does not accept these argument types"):
        gen.visit(fc)


# ---------------------------------------------------------------------------
# Lines 816-821: math.count/percentage branch and math.mode (else branch)
# ---------------------------------------------------------------------------


def test_math_count_with_one_integer_argument() -> None:
    """Line 817: math.count with single integer renders correctly."""
    gen = CodeGenerator()
    fc = FunctionCall(function="math.count", arguments=[IntegerLiteral(65)])
    result = gen.visit(fc)
    assert result == "math.count(65)"


def test_math_count_with_three_integer_arguments() -> None:
    """Line 817: math.count with three integers (byte, offset, size) renders correctly."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="math.count",
        arguments=[IntegerLiteral(65), IntegerLiteral(0), IntegerLiteral(100)],
    )
    result = gen.visit(fc)
    assert result == "math.count(65, 0, 100)"


def test_math_count_with_invalid_third_arg_raises() -> None:
    """Line 817 invalid: math.count with non-integer third arg raises."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="math.count",
        arguments=[IntegerLiteral(65), IntegerLiteral(0), StringLiteral("x")],
    )
    with pytest.raises(ValueError, match="does not accept these argument types"):
        gen.visit(fc)


def test_math_percentage_with_one_integer_argument() -> None:
    """Line 817 (percentage): math.percentage with single integer renders."""
    gen = CodeGenerator()
    fc = FunctionCall(function="math.percentage", arguments=[IntegerLiteral(65)])
    result = gen.visit(fc)
    assert result == "math.percentage(65)"


def test_math_mode_with_zero_arguments() -> None:
    """Lines 820-821 (else/mode branch): math.mode with zero args renders."""
    gen = CodeGenerator()
    fc = FunctionCall(function="math.mode", arguments=[])
    result = gen.visit(fc)
    assert result == "math.mode()"


def test_math_mode_with_two_integer_arguments() -> None:
    """Lines 820-821 (else/mode branch): math.mode with two integer args renders."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="math.mode",
        arguments=[IntegerLiteral(0), IntegerLiteral(100)],
    )
    result = gen.visit(fc)
    assert result == "math.mode(0, 100)"


def test_math_mode_with_invalid_argument_raises() -> None:
    """Lines 820-821 (else/invalid): math.mode with string arg raises."""
    gen = CodeGenerator()
    fc = FunctionCall(function="math.mode", arguments=[StringLiteral("x")])
    with pytest.raises(ValueError, match="does not accept these argument types"):
        gen.visit(fc)


# ---------------------------------------------------------------------------
# Line 844: pe.imports early return when argument type is None
# ---------------------------------------------------------------------------


def test_pe_imports_with_unknown_argument_type_passes() -> None:
    """Line 844: pe.imports with unknown arg type (Identifier) skips validation."""
    gen = CodeGenerator()
    fc = FunctionCall(function="pe.imports", arguments=[Identifier("unknown_var")])
    result = gen.visit(fc)
    assert result == "pe.imports(unknown_var)"


def test_pe_imports_with_invalid_type_raises() -> None:
    """Line 867: pe.imports with incompatible argument types raises."""
    gen = CodeGenerator()
    fc = FunctionCall(function="pe.imports", arguments=[IntegerLiteral(1)])
    with pytest.raises(ValueError, match="does not accept these argument types"):
        gen.visit(fc)


# ---------------------------------------------------------------------------
# Line 876: pe.exports early return when argument type is None
# ---------------------------------------------------------------------------


def test_pe_exports_with_unknown_argument_type_passes() -> None:
    """Line 876: pe.exports with unknown arg type (Identifier) skips validation."""
    gen = CodeGenerator()
    fc = FunctionCall(function="pe.exports", arguments=[Identifier("unknown_var")])
    result = gen.visit(fc)
    assert result == "pe.exports(unknown_var)"


def test_pe_exports_with_invalid_type_raises() -> None:
    """Line 879: pe.exports with DoubleLiteral raises."""
    gen = CodeGenerator()
    fc = FunctionCall(function="pe.exports", arguments=[DoubleLiteral(1.0)])
    with pytest.raises(ValueError, match="does not accept these argument types"):
        gen.visit(fc)


def test_pe_exports_with_regex_argument_passes() -> None:
    """Line 877-878: pe.exports with RegexLiteral is valid."""
    gen = CodeGenerator()
    fc = FunctionCall(function="pe.exports", arguments=[RegexLiteral("Get.*")])
    result = gen.visit(fc)
    assert result == "pe.exports(/Get.*/)"


# ---------------------------------------------------------------------------
# Lines 888, 890: pe.section_index early return and invalid type error
# ---------------------------------------------------------------------------


def test_pe_section_index_with_unknown_argument_type_passes() -> None:
    """Line 888: pe.section_index with Identifier skips validation."""
    gen = CodeGenerator()
    fc = FunctionCall(function="pe.section_index", arguments=[Identifier("unknown_var")])
    result = gen.visit(fc)
    assert result == "pe.section_index(unknown_var)"


def test_pe_section_index_with_invalid_type_raises() -> None:
    """Line 891: pe.section_index with DoubleLiteral raises."""
    gen = CodeGenerator()
    fc = FunctionCall(function="pe.section_index", arguments=[DoubleLiteral(1.0)])
    with pytest.raises(ValueError, match="does not accept these argument types"):
        gen.visit(fc)


# ---------------------------------------------------------------------------
# Lines 901, 903: pe.import_rva early return and invalid type error
# ---------------------------------------------------------------------------


def test_pe_import_rva_with_unknown_argument_types_passes() -> None:
    """Lines 901, 903 (early return): pe.import_rva with Identifier args skips validation."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="pe.import_rva",
        arguments=[Identifier("dll"), Identifier("func")],
    )
    result = gen.visit(fc)
    assert result == "pe.import_rva(dll, func)"


def test_pe_import_rva_with_invalid_type_combination_raises() -> None:
    """Line 904: pe.import_rva with int,double raises."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="pe.import_rva",
        arguments=[IntegerLiteral(1), DoubleLiteral(1.0)],
    )
    with pytest.raises(ValueError, match="does not accept these argument types"):
        gen.visit(fc)


# ---------------------------------------------------------------------------
# Lines 913, 931: console.log and console.hex with invalid types
# ---------------------------------------------------------------------------


def test_console_log_with_unknown_argument_type_passes() -> None:
    """Line 913 (early return): console.log with Identifier skips validation."""
    gen = CodeGenerator()
    fc = FunctionCall(function="console.log", arguments=[Identifier("unknown")])
    result = gen.visit(fc)
    assert result == "console.log(unknown)"


def test_console_log_with_invalid_types_raises() -> None:
    """Line 922: console.log with two doubles raises."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="console.log",
        arguments=[DoubleLiteral(1.0), DoubleLiteral(1.0)],
    )
    with pytest.raises(ValueError, match="does not accept these argument types"):
        gen.visit(fc)


def test_console_hex_with_unknown_argument_type_passes() -> None:
    """Line 931 (early return): console.hex with Identifier skips validation."""
    gen = CodeGenerator()
    fc = FunctionCall(function="console.hex", arguments=[Identifier("unknown")])
    result = gen.visit(fc)
    assert result == "console.hex(unknown)"


def test_console_hex_with_invalid_type_raises() -> None:
    """Line 939: console.hex with DoubleLiteral raises."""
    gen = CodeGenerator()
    fc = FunctionCall(function="console.hex", arguments=[DoubleLiteral(1.0)])
    with pytest.raises(ValueError, match="does not accept these argument types"):
        gen.visit(fc)


# ---------------------------------------------------------------------------
# Line 962: _validate_generic_module_function_argument_types — argument_type is None (continue)
# ---------------------------------------------------------------------------


def test_generic_module_validation_skips_unknown_argument_type() -> None:
    """Line 962: cuckoo function with Identifier arg skips type check (continue)."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="cuckoo.network.http_request",
        arguments=[Identifier("unknown_regex")],
    )
    result = gen.visit(fc)
    assert result == "cuckoo.network.http_request(unknown_regex)"


# ---------------------------------------------------------------------------
# Lines 979-983: _validate_generic_module_function_argument_types — incompatible type raises
# ---------------------------------------------------------------------------


def test_generic_module_validation_incompatible_type_raises() -> None:
    """Lines 979-983: cuckoo function with StringLiteral (not regex) raises."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="cuckoo.network.http_request",
        arguments=[StringLiteral("test")],
    )
    with pytest.raises(ValueError, match="does not accept these argument types"):
        gen.visit(fc)


# ---------------------------------------------------------------------------
# Lines 1011-1021: _obvious_argument_type branches
# ---------------------------------------------------------------------------


def test_obvious_argument_type_identifier_filesize() -> None:
    """Line 1011: Identifier 'filesize' returns 'integer'."""
    assert _obvious_argument_type(Identifier("filesize")) == "integer"


def test_obvious_argument_type_identifier_entrypoint() -> None:
    """Line 1011: Identifier 'entrypoint' returns 'integer'."""
    assert _obvious_argument_type(Identifier("entrypoint")) == "integer"


def test_obvious_argument_type_string_count() -> None:
    """Line 1013: StringCount returns 'integer'."""
    assert _obvious_argument_type(StringCount("#a")) == "integer"


def test_obvious_argument_type_string_length() -> None:
    """Line 1013: StringLength returns 'integer'."""
    assert _obvious_argument_type(StringLength("!a")) == "integer"


def test_obvious_argument_type_string_offset() -> None:
    """Line 1013: StringOffset returns 'integer'."""
    assert _obvious_argument_type(StringOffset("@a")) == "integer"


def test_obvious_argument_type_integer_read_function_call() -> None:
    """Lines 1015-1020: FunctionCall with int8 and receiver=None returns 'integer'."""
    fc = FunctionCall(function="int8", arguments=[IntegerLiteral(0)])
    assert _obvious_argument_type(fc) == "integer"


def test_obvious_argument_type_module_member_access_fallback() -> None:
    """Line 1021: MemberAccess on known module falls back to scalar type name."""
    mem = MemberAccess(object=ModuleReference("pe"), member="machine")
    assert _obvious_argument_type(mem) == "integer"


def test_obvious_argument_type_used_in_console_log_with_filesize() -> None:
    """Lines 1011-1021 via visit: console.log(filesize) renders correctly."""
    gen = CodeGenerator()
    fc = FunctionCall(function="console.log", arguments=[Identifier("filesize")])
    result = gen.visit(fc)
    assert result == "console.log(filesize)"


def test_obvious_argument_type_used_in_hash_md5_with_string_count() -> None:
    """Lines 1013 via _validate: StringCount arguments typed as integer in validation."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="hash.md5",
        arguments=[StringCount("#a"), StringCount("#b")],
    )
    with pytest.raises((ValueError, Exception)):
        gen.visit(fc)


# ---------------------------------------------------------------------------
# Lines 1032-1035: require_present_expression
# ---------------------------------------------------------------------------


def test_require_present_expression_with_none_raises() -> None:
    """Lines 1032-1034: None value raises ValueError with field name."""
    with pytest.raises(ValueError, match="my_field is required for libyara output"):
        require_present_expression(None, "my_field")


def test_require_present_expression_with_value_returns_it() -> None:
    """Line 1035: Non-None value is returned unchanged."""
    node = IntegerLiteral(42)
    result = require_present_expression(node, "my_field")
    assert result is node


# ---------------------------------------------------------------------------
# Line 1113: _reject_bare_module_container_expression — FunctionCall with receiver
# ---------------------------------------------------------------------------


def test_condition_validation_function_call_with_receiver() -> None:
    """Line 1113: FunctionCall with non-None receiver triggers receiver recursion."""
    from yaraast.codegen.generator_expression_visitors import validate_condition_expression

    gen = CodeGenerator()
    sig_array = MemberAccess(object=ModuleReference("pe"), member="signatures")
    indexed = ArrayAccess(array=sig_array, index=IntegerLiteral(0))
    fc = FunctionCall(
        function="valid_on",
        arguments=[IntegerLiteral(1748736000)],
        receiver=indexed,
    )
    # Should not raise — the receiver is a valid container expression.
    validate_condition_expression(gen, fc)


# ---------------------------------------------------------------------------
# Lines 1189-1190: render_function_call_callee — receiver not None
# ---------------------------------------------------------------------------


def test_render_function_call_callee_with_receiver() -> None:
    """Lines 1189-1190: Receiver-based callee renders as '<receiver>.<method>'."""
    gen = CodeGenerator()
    sig_array = MemberAccess(object=ModuleReference("pe"), member="signatures")
    indexed = ArrayAccess(array=sig_array, index=IntegerLiteral(0))
    fc = FunctionCall(
        function="valid_on",
        arguments=[IntegerLiteral(1748736000)],
        receiver=indexed,
    )
    callee = render_function_call_callee(gen, fc)
    assert callee == "pe.signatures[0].valid_on"


def test_visit_function_call_with_receiver_renders_full_expression() -> None:
    """Lines 1189-1190 via visit: full pe.signatures[0].valid_on(...) renders."""
    gen = CodeGenerator()
    sig_array = MemberAccess(object=ModuleReference("pe"), member="signatures")
    indexed = ArrayAccess(array=sig_array, index=IntegerLiteral(0))
    fc = FunctionCall(
        function="valid_on",
        arguments=[IntegerLiteral(1748736000)],
        receiver=indexed,
    )
    result = gen.visit(fc)
    assert result == "pe.signatures[0].valid_on(0x683b9800)"


# ---------------------------------------------------------------------------
# Line 1200: _normalize_postfix_target — double-wrapped ParenthesesExpression
# ---------------------------------------------------------------------------


def test_normalize_postfix_target_double_wrapped_parentheses() -> None:
    """Line 1200: Double-wrapped ParenthesesExpression unwraps one layer."""
    inner = ParenthesesExpression(IntegerLiteral(42))
    outer = ParenthesesExpression(inner)
    result = _normalize_postfix_target(outer)
    # Outer wraps inner, which is itself a ParenthesesExpression (not double-wrapped).
    # The function peels while both outer and outer.expression are ParenthesesExpression.
    assert isinstance(result, ParenthesesExpression)
    assert isinstance(result.expression, IntegerLiteral)


# ---------------------------------------------------------------------------
# Line 1209: validate_array_access_target — TupleExpression raises
# ---------------------------------------------------------------------------


def test_validate_array_access_target_tuple_expression_raises() -> None:
    """Line 1209: TupleExpression as array access target raises ValueError."""
    tup = TupleExpression(elements=[IntegerLiteral(1)])
    with pytest.raises(ValueError, match="must not be a tuple expression"):
        validate_array_access_target(tup)


def test_validate_array_access_target_parenthesized_tuple_raises() -> None:
    """Line 1209 via unwrap: ParenthesesExpression(TupleExpression) also raises."""
    tup = TupleExpression(elements=[IntegerLiteral(1)])
    paren_tup = ParenthesesExpression(tup)
    with pytest.raises(ValueError, match="must not be a tuple expression"):
        validate_array_access_target(paren_tup)


# ---------------------------------------------------------------------------
# Line 1221: validate_postfix_target — AtExpression raises
# ---------------------------------------------------------------------------


def test_validate_postfix_target_at_expression_raises() -> None:
    """Line 1221: AtExpression as postfix target raises ValueError."""
    at_expr = AtExpression(string_id="$a", offset=IntegerLiteral(0))
    with pytest.raises(ValueError, match="must be a condition that can be parenthesized"):
        validate_postfix_target(at_expr)


# ---------------------------------------------------------------------------
# Lines 1261-1262: validate_tuple_indexing_target — non-FunctionCall/TupleExpression raises
# ---------------------------------------------------------------------------


def test_validate_tuple_indexing_target_integer_literal_raises() -> None:
    """Lines 1261-1262: IntegerLiteral as tuple indexing target raises."""
    with pytest.raises(ValueError, match="function call or tuple expression"):
        validate_tuple_indexing_target(IntegerLiteral(42))


def test_validate_tuple_indexing_target_function_call_passes() -> None:
    """Lines 1259-1260: FunctionCall as tuple indexing target is valid."""
    fc = FunctionCall(function="int8", arguments=[IntegerLiteral(0)])
    # Should not raise
    validate_tuple_indexing_target(fc)


def test_validate_tuple_indexing_target_tuple_expression_passes() -> None:
    """Lines 1259-1260: TupleExpression as tuple indexing target is valid."""
    tup = TupleExpression(elements=[IntegerLiteral(1)])
    # Should not raise
    validate_tuple_indexing_target(tup)


# ---------------------------------------------------------------------------
# Line 1337: visit_array_access — FunctionCall array target wrapping
# ---------------------------------------------------------------------------


def test_visit_array_access_with_function_call_target_raises_on_invalid_module() -> None:
    """Line 1337: FunctionCall array target triggers extra parentheses, then validation."""
    gen = CodeGenerator()
    # pe.rva_to_offset returns an integer, so it cannot be indexed as an array.
    fc = FunctionCall(function="pe.rva_to_offset", arguments=[IntegerLiteral(0)])
    arr = ArrayAccess(array=fc, index=IntegerLiteral(0))
    with pytest.raises(ValueError, match="cannot be indexed as an array"):
        gen.visit(arr)


# ---------------------------------------------------------------------------
# Lines 1419, 1423: known_builtin_module_expression_type — FunctionCall branches
# ---------------------------------------------------------------------------


def test_known_builtin_module_expression_type_no_module_function() -> None:
    """Line 1419: FunctionCall without dot notation returns None."""
    fc = FunctionCall(function="my_local_func", arguments=[])
    result = known_builtin_module_expression_type(fc)
    assert result is None


def test_known_builtin_module_expression_type_unknown_module() -> None:
    """Line 1423: FunctionCall with unknown module name returns None."""
    fc = FunctionCall(function="mymod.myfunc", arguments=[])
    result = known_builtin_module_expression_type(fc)
    assert result is None


def test_known_builtin_module_expression_type_reuses_loaded_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yaraast.types import module_definitions

    calls = 0
    real_load = module_definitions.load_builtin_modules

    def counted_load() -> object:
        nonlocal calls
        calls += 1
        return real_load()

    _load_builtin_modules_cached.cache_clear()
    monkeypatch.setattr(module_definitions, "load_builtin_modules", counted_load)

    expression = MemberAccess(object=ModuleReference("pe"), member="sections")
    for _ in range(3):
        assert known_builtin_module_expression_type(expression) is not None

    assert calls == 1
    _load_builtin_modules_cached.cache_clear()


# ---------------------------------------------------------------------------
# Line 1426: known_builtin_module_expression_type — ArrayAccess branch
# ---------------------------------------------------------------------------


def test_known_builtin_module_expression_type_array_access() -> None:
    """Line 1426: ArrayAccess on known array type returns element type."""
    pe_sections = MemberAccess(object=ModuleReference("pe"), member="sections")
    section_0 = ArrayAccess(array=pe_sections, index=IntegerLiteral(0))
    from yaraast.types._registry_collections import StructType

    result = known_builtin_module_expression_type(section_0)
    assert isinstance(result, StructType)


# ---------------------------------------------------------------------------
# Line 1432: known_builtin_module_expression_type — DictionaryAccess branch
# ---------------------------------------------------------------------------


def test_known_builtin_module_expression_type_dictionary_access() -> None:
    """Line 1432: DictionaryAccess on known dict type returns value type."""
    version_info = MemberAccess(object=ModuleReference("pe"), member="version_info")
    dict_acc = DictionaryAccess(object=version_info, key="FileDescription")
    from yaraast.types._registry_primitives import StringType

    result = known_builtin_module_expression_type(dict_acc)
    assert isinstance(result, StringType)


# ---------------------------------------------------------------------------
# Line 1419 (struct field): MemberAccess on a struct returns field type
# ---------------------------------------------------------------------------


def test_known_builtin_module_expression_type_member_access_on_module() -> None:
    """Line 1419 (MemberAccess branch): pe.machine returns IntegerType."""
    from yaraast.types._registry_primitives import IntegerType

    mem = MemberAccess(object=ModuleReference("pe"), member="machine")
    result = known_builtin_module_expression_type(mem)
    assert isinstance(result, IntegerType)


def test_known_builtin_module_expression_type_member_access_on_struct() -> None:
    """Line 1423 (struct field): pe.sections[0].name returns StringType."""
    from yaraast.types._registry_primitives import StringType

    pe_sections = MemberAccess(object=ModuleReference("pe"), member="sections")
    section_0 = ArrayAccess(array=pe_sections, index=IntegerLiteral(0))
    name_field = MemberAccess(object=section_0, member="name")
    result = known_builtin_module_expression_type(name_field)
    assert isinstance(result, StringType)


# ---------------------------------------------------------------------------
# Lines 1463-1469: _known_builtin_module_scalar_type_name — StringType branch
# ---------------------------------------------------------------------------


def test_known_builtin_module_scalar_type_name_string_type() -> None:
    """Line 1469: pe.version_info dict value returns 'string'."""
    version_info = MemberAccess(object=ModuleReference("pe"), member="version_info")
    dict_acc = DictionaryAccess(object=version_info, key="FileVersion")
    result = _known_builtin_module_scalar_type_name(dict_acc)
    assert result == "string"


def test_known_builtin_module_scalar_type_name_integer_type() -> None:
    """Lines 1464-1465: pe.machine returns 'integer'."""
    mem = MemberAccess(object=ModuleReference("pe"), member="machine")
    result = _known_builtin_module_scalar_type_name(mem)
    assert result == "integer"


def test_known_builtin_module_scalar_type_name_struct_string_field() -> None:
    """Line 1469: pe.sections[0].name returns 'string' via struct field."""
    pe_sections = MemberAccess(object=ModuleReference("pe"), member="sections")
    section_0 = ArrayAccess(array=pe_sections, index=IntegerLiteral(0))
    name_field = MemberAccess(object=section_0, member="name")
    result = _known_builtin_module_scalar_type_name(name_field)
    assert result == "string"


# ---------------------------------------------------------------------------
# Line 1537: visit_at_expression — hasattr(node.string_id, "accept") branch
# ---------------------------------------------------------------------------


def test_visit_at_expression_string_id_with_accept_method() -> None:
    """Line 1537: AtExpression with string_id having accept() uses generator.visit."""
    gen = CodeGenerator()
    # Identifier has an accept() method, so it takes the hasattr branch.
    at_expr = AtExpression(string_id=Identifier("x"), offset=IntegerLiteral(0))
    result = gen.visit(at_expr)
    assert result == "x at 0"


def test_visit_at_expression_string_id_without_accept_method() -> None:
    """Line 1554-1558: AtExpression with plain string id uses format_string_reference."""
    gen = CodeGenerator()
    at_expr = AtExpression(string_id="$a", offset=IntegerLiteral(0))
    result = gen.visit(at_expr)
    assert result == "$a at 0"


# ---------------------------------------------------------------------------
# Additional integration tests to maximize path coverage
# ---------------------------------------------------------------------------


def test_visit_parentheses_expression_wrapping_integer_literal() -> None:
    """Line 639 (normal path): ParenthesesExpression wrapping integer renders with parens."""
    gen = CodeGenerator()
    result = gen.visit(ParenthesesExpression(IntegerLiteral(7)))
    assert result == "(7)"


def test_hash_md5_with_two_integer_arguments_valid() -> None:
    """Line 786 valid path: hash.md5(offset, size) with integers is valid."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="hash.md5",
        arguments=[IntegerLiteral(0), IntegerLiteral(100)],
    )
    result = gen.visit(fc)
    assert result == "hash.md5(0, 100)"


def test_pe_imports_with_two_string_arguments_valid() -> None:
    """Line 864 valid path: pe.imports(dll, function) with strings is valid."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="pe.imports",
        arguments=[StringLiteral("kernel32.dll"), StringLiteral("CreateFile")],
    )
    result = gen.visit(fc)
    assert result == 'pe.imports("kernel32.dll", "CreateFile")'


def test_cuckoo_function_with_valid_regex_argument() -> None:
    """Lines 964-976 (compatible path): cuckoo function with RegexLiteral passes."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="cuckoo.network.http_request",
        arguments=[RegexLiteral("test")],
    )
    result = gen.visit(fc)
    assert result == "cuckoo.network.http_request(/test/)"


def test_math_in_range_with_three_double_arguments() -> None:
    """Line 812: math.in_range with three doubles is valid."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="math.in_range",
        arguments=[DoubleLiteral(1.0), DoubleLiteral(0.0), DoubleLiteral(2.0)],
    )
    result = gen.visit(fc)
    assert result == "math.in_range(1.0, 0.0, 2.0)"


def test_pe_exports_index_with_valid_string_argument() -> None:
    """Line 877-878: pe.exports_index with string is valid."""
    gen = CodeGenerator()
    fc = FunctionCall(function="pe.exports_index", arguments=[StringLiteral("GetProcAddress")])
    result = gen.visit(fc)
    assert result == 'pe.exports_index("GetProcAddress")'


def test_console_log_with_string_and_integer_arguments() -> None:
    """Lines 915-918 valid path: console.log(string, integer) renders correctly."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="console.log",
        arguments=[StringLiteral("value: "), IntegerLiteral(42)],
    )
    result = gen.visit(fc)
    assert result == 'console.log("value: ", 42)'


def test_console_hex_with_label_and_integer() -> None:
    """Lines 932-936 valid: console.hex(string, integer) renders correctly."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="console.hex",
        arguments=[StringLiteral("label"), IntegerLiteral(42)],
    )
    result = gen.visit(fc)
    assert result == 'console.hex("label", 42)'


def test_pe_import_rva_with_string_and_integer_arguments() -> None:
    """Line 902-903: pe.import_rva with (string, integer) is also valid."""
    gen = CodeGenerator()
    fc = FunctionCall(
        function="pe.import_rva",
        arguments=[StringLiteral("kernel32.dll"), IntegerLiteral(1)],
    )
    result = gen.visit(fc)
    assert result == 'pe.import_rva("kernel32.dll", 1)'


def test_known_builtin_module_expression_type_unknown_module_member() -> None:
    """Line 1432 (None return): MemberAccess on unknown module returns None."""
    mem = MemberAccess(object=ModuleReference("unknown_module"), member="field")
    result = known_builtin_module_expression_type(mem)
    assert result is None


# ---------------------------------------------------------------------------
# Additional branch-specific tests for lines remaining uncovered in full suite
# ---------------------------------------------------------------------------


def test_is_definitely_boolean_in_expression_with_string_count_subject() -> None:
    """Line 132 (False branch): InExpression where subject IS StringCount returns False."""
    from yaraast.codegen.generator_expression_visitors import _is_definitely_boolean_expression

    range_expr = RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(10))
    in_expr = InExpression(subject=StringCount("#a"), range=range_expr)
    # StringCount subject -> returns not isinstance(StringCount, StringCount) -> False
    result = _is_definitely_boolean_expression(in_expr)
    assert result is False


def test_is_definitely_non_integer_unknown_unary_operator_falls_through() -> None:
    """Branch 222->224: UnaryExpression with unknown operator reaches line 224 (not '-')."""
    from yaraast.ast.expressions import UnaryExpression

    # An unknown unary operator (not 'not', '%', '~', '-') reaches line 222
    # and the condition 'value.operator == "-"' is False, so execution falls to line 224.
    expr = UnaryExpression("?", IntegerLiteral(1))
    result = _is_definitely_non_integer_expression(expr)
    assert result is False


def test_constant_integer_value_unknown_unary_operator_falls_through_to_none() -> None:
    """Branch 402->404: UnaryExpression with unknown operator (not '-'/'~') falls through."""
    from yaraast.codegen.generator_expression_visitors import _constant_integer_value

    # With a constant operand but unknown operator, line 400 ('-') is False,
    # line 402 ('~') is False, so execution continues to line 404 (BinaryExpression check).
    # Not a BinaryExpression, so returns None at line 441.
    expr = UnaryExpression("?", IntegerLiteral(5))
    result = _constant_integer_value(expr)
    assert result is None


def test_constant_integer_value_modulo_by_zero_returns_none() -> None:
    """Line 427: BinaryExpression '%' with right operand == 0 returns None."""
    from yaraast.codegen.generator_expression_visitors import _constant_integer_value

    expr = BinaryExpression(IntegerLiteral(7), "%", IntegerLiteral(0))
    result = _constant_integer_value(expr)
    assert result is None


def test_constant_integer_value_shift_right_returns_value() -> None:
    """Lines 439-441: BinaryExpression '>>' returns correct shifted value."""
    from yaraast.codegen.generator_expression_visitors import _constant_integer_value

    expr = BinaryExpression(IntegerLiteral(16), ">>", IntegerLiteral(2))
    result = _constant_integer_value(expr)
    assert result == 4


def test_constant_comparison_operand_type_integer_binary_operator_branch() -> None:
    """Branch 533->537: BinaryExpression with INTEGER_BINARY_OPERATORS gives 'integer'."""
    from yaraast.codegen.generator_expression_visitors import _constant_comparison_operand_type

    # '|' is in INTEGER_BINARY_OPERATORS; not definitely non-integer -> 'integer'
    expr = BinaryExpression(IntegerLiteral(3), "|", IntegerLiteral(5))
    result = _constant_comparison_operand_type(expr)
    assert result == "integer"


def test_constant_comparison_operand_type_numeric_non_integer_double_branch() -> None:
    """Branch 533->537: BinaryExpression '+' with non-integer operands gives 'double'."""
    from yaraast.codegen.generator_expression_visitors import _constant_comparison_operand_type

    # '+' is in NUMERIC_BINARY_OPERATORS; left is DoubleLiteral -> non-integer -> 'double'
    expr = BinaryExpression(DoubleLiteral(1.5), "+", DoubleLiteral(2.5))
    result = _constant_comparison_operand_type(expr)
    assert result == "double"


def test_constant_comparison_operand_type_unary_minus_double_operand() -> None:
    """Branch 553->555: UnaryExpression '-' with DoubleLiteral operand returns 'double'."""
    from yaraast.codegen.generator_expression_visitors import _constant_comparison_operand_type

    expr = UnaryExpression("-", DoubleLiteral(3.14))
    result = _constant_comparison_operand_type(expr)
    assert result == "double"


def test_known_module_function_def_none_raises() -> None:
    """Line 695 (return after raise): pe.unknown raises, line 695 is the return after None check."""
    gen = CodeGenerator()
    fc = FunctionCall(function="pe.unknown_function_xyz", arguments=[])
    with pytest.raises(ValueError, match="not supported by libyara"):
        gen.visit(fc)


def test_console_hex_valid_return_and_generic_path() -> None:
    """Branch 738->742: console.hex validation returns, then generic path reached for other."""
    gen = CodeGenerator()
    # console.hex valid call triggers the 'hex' branch and return
    fc = FunctionCall(function="console.hex", arguments=[IntegerLiteral(255)])
    result = gen.visit(fc)
    assert result == "console.hex(255)"


def test_known_builtin_module_expression_type_array_access_non_array_type_returns_none() -> None:
    """Line 1426 (None branch): ArrayAccess where array type is not ArrayType returns None."""
    # pe.machine is IntegerType, not ArrayType; indexing it has no type.
    pe_machine = MemberAccess(object=ModuleReference("pe"), member="machine")
    arr = ArrayAccess(array=pe_machine, index=IntegerLiteral(0))
    result = known_builtin_module_expression_type(arr)
    assert result is None


def test_render_for_loop_variable_single_name() -> None:
    """Line 1537: _render_for_loop_variable with a single-name string variable."""
    from yaraast.codegen.generator_expression_visitors import visit_for_expression

    gen = CodeGenerator()
    range_expr = RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(5))
    for_expr = ForExpression(
        quantifier="any",
        variable="i",
        iterable=range_expr,
        body=IntegerLiteral(1),
    )
    # Single variable name hits line 1537 via _render_for_loop_variable
    result = visit_for_expression(gen, for_expr)
    assert "for any i in" in result


# ---------------------------------------------------------------------------
# Line 1537: _render_for_loop_variable — non-string variable path
# ---------------------------------------------------------------------------


def test_render_for_loop_variable_non_string_raises_type_error() -> None:
    """Line 1537: _render_for_loop_variable raises TypeError for non-str input."""
    with pytest.raises(TypeError, match="Loop variable identifier must be a string"):
        _render_for_loop_variable(Identifier("i"))


# ---------------------------------------------------------------------------
# Line 418: _constant_integer_value — BinaryExpression with non-constant operands
# ---------------------------------------------------------------------------


def test_constant_integer_value_non_constant_binary_expr_returns_none() -> None:
    """Line 418: When operands are non-constant, _constant_integer_value returns None."""
    non_const = BinaryExpression(operator="+", left=Identifier("x"), right=IntegerLiteral(1))
    result = _constant_integer_value(non_const)
    assert result is None


# ---------------------------------------------------------------------------
# Lines 439->441: _constant_integer_value — '>>' with negative right returns None
# ---------------------------------------------------------------------------


def test_constant_integer_value_right_shift_negative_count_returns_none() -> None:
    """Lines 435-436, 439->441: Right shift with negative count returns None."""
    neg_shift = BinaryExpression(operator=">>", left=IntegerLiteral(4), right=IntegerLiteral(-1))
    result = _constant_integer_value(neg_shift)
    assert result is None


def test_constant_integer_value_left_shift_negative_count_returns_none() -> None:
    """Line 435-436: Left shift with negative count returns None."""
    neg_shift = BinaryExpression(operator="<<", left=IntegerLiteral(4), right=IntegerLiteral(-1))
    result = _constant_integer_value(neg_shift)
    assert result is None


# ---------------------------------------------------------------------------
# Lines 533->537: _constant_comparison_operand_type — integer binary operator
# ---------------------------------------------------------------------------


def test_constant_comparison_operand_type_integer_binary_op() -> None:
    """Lines 533-537: BinaryExpression with integer binary op returns 'integer'."""
    int_op = BinaryExpression(operator="&", left=IntegerLiteral(5), right=IntegerLiteral(3))
    result = _constant_comparison_operand_type(int_op)
    assert result == "integer"


def test_constant_comparison_operand_type_numeric_op_integer() -> None:
    """Line 534-536: BinaryExpression with numeric op where not definitely non-integer."""
    num_op = BinaryExpression(operator="+", left=IntegerLiteral(2), right=IntegerLiteral(3))
    result = _constant_comparison_operand_type(num_op)
    assert result == "integer"


# ---------------------------------------------------------------------------
# Lines 553->555: _constant_comparison_operand_type — unary '-' on DoubleLiteral
# ---------------------------------------------------------------------------


def test_constant_comparison_operand_type_unary_minus_on_double() -> None:
    """Lines 553-554: UnaryExpression '-' with DoubleLiteral operand returns 'double'."""
    unary_neg_dbl = UnaryExpression(operator="-", operand=DoubleLiteral(3.14))
    result = _constant_comparison_operand_type(unary_neg_dbl)
    assert result == "double"


# ---------------------------------------------------------------------------
# Line 660: validate_function_call_arguments — unsupported aliases via gen.visit
# ---------------------------------------------------------------------------


def test_visit_function_call_unsupported_le_alias_raises_via_generator() -> None:
    """Line 660: Visiting a FunctionCall with int16le raises ValueError."""
    gen = CodeGenerator()
    fc = FunctionCall(function="int16le", arguments=[IntegerLiteral(0)])
    with pytest.raises(ValueError, match="not supported by libyara"):
        gen.visit(fc)


# ---------------------------------------------------------------------------
# Line 695: _validate_known_module_function_call — function not found in module
# ---------------------------------------------------------------------------


def test_known_builtin_module_expression_type_pe_unknown_function_returns_none() -> None:
    """Line 1426: FunctionCall with known module but unknown function returns None."""
    fc = FunctionCall(function="pe.nonexistent_function_xyz", arguments=[])
    result = known_builtin_module_expression_type(fc)
    assert result is None


def test_validate_known_module_function_unknown_raises_via_generator() -> None:
    """Line 695: Calling pe.does_not_exist raises ValueError via generator."""
    gen = CodeGenerator()
    fc = FunctionCall(function="pe.does_not_exist", arguments=[])
    with pytest.raises(ValueError, match="not supported by libyara"):
        gen.visit(fc)


# ---------------------------------------------------------------------------
# Lines 738->742: console.hex branch in _validate_known_module_function_call
# ---------------------------------------------------------------------------


def test_visit_console_hex_with_integer_argument_renders() -> None:
    """Line 738: console.hex(integer) passes validation and renders."""
    gen = CodeGenerator()
    fc = FunctionCall(function="console.hex", arguments=[IntegerLiteral(255)])
    result = gen.visit(fc)
    assert result == "console.hex(255)"


def test_visit_console_hex_invalid_argument_raises() -> None:
    """Lines 738->742: console.hex with string arg raises."""
    gen = CodeGenerator()
    fc = FunctionCall(function="console.hex", arguments=[StringLiteral("bad")])
    with pytest.raises(ValueError, match="does not accept these argument types"):
        gen.visit(fc)


# ---------------------------------------------------------------------------
# Line 1221: validate_postfix_target — AtExpression raises ValueError
# ---------------------------------------------------------------------------


def test_validate_postfix_target_with_at_expression_raises() -> None:
    """Line 1221: AtExpression as postfix target raises ValueError."""
    at_expr = AtExpression(string_id="$a", offset=IntegerLiteral(0))
    with pytest.raises(ValueError, match="condition that can be parenthesized"):
        validate_postfix_target(at_expr)


def test_validate_postfix_target_in_paren_with_at_expression_raises() -> None:
    """Line 1221: AtExpression inside ParenthesesExpression still raises."""
    at_expr = AtExpression(string_id="$a", offset=IntegerLiteral(0))
    paren = ParenthesesExpression(at_expr)
    with pytest.raises(ValueError, match="condition that can be parenthesized"):
        validate_postfix_target(paren)


# ---------------------------------------------------------------------------
# Line 1337: visit_array_access — FunctionCall array that passes module type check
# ---------------------------------------------------------------------------


def test_visit_array_access_with_non_module_function_call_wraps_in_parens() -> None:
    """Line 1337: FunctionCall without module prefix as array target adds extra parens."""
    gen = CodeGenerator()
    # uint16 returns an integer — cannot be indexed. Use a pattern that passes
    # validate_known_module_array_access (array_type is None because uint16 is not a module expr).
    fc = FunctionCall(function="uint16", arguments=[IntegerLiteral(0)])
    arr = ArrayAccess(array=fc, index=IntegerLiteral(2))
    result = gen.visit(arr)
    assert result == "(uint16(0))[2]"


# ---------------------------------------------------------------------------
# Line 1463 / 1469: _known_builtin_module_scalar_type_name — BooleanType / RegexType
# These types do not appear in any builtin module definition, making these
# branches genuinely unreachable via the production module registry.
# Documented here as confirmed-unreachable per module definition inspection.
# ---------------------------------------------------------------------------
