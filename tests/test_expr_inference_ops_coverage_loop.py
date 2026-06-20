# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered lines in yaraast/types/_expr_inference_ops.py.

Each test constructs real AST nodes and runs them through the actual inference
engine so that coverage reflects genuine code execution, not artificial stubs.
"""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.modules import DictionaryAccess
from yaraast.types._expr_inference import ExpressionTypeInference
from yaraast.types._expr_inference_ops import (
    _classify_of_set_value,
    _constant_integer_value,
    _define_for_iteration_variables,
    _has_invalid_static_percentage_operand,
    _has_unknown_comparison_operand,
    _infer_dictionary_key_type,
    _infer_quantifier_value,
    _infer_set_element_type,
    _infer_string_set_value,
    _is_function_argument_compatible,
    _is_literal_boolean_comparison_operand,
    _is_percentage_quantifier_value,
    _is_string_set_element,
    _lookup_string_set_local,
    _static_integer_value,
    _validate_function_argument_types,
    _validate_hash_function_arguments,
    _validate_math_function_arguments,
    _validate_pe_import_rva_arguments,
    _validate_quantifier_text_value,
    _validate_quantifier_value,
    _validate_rule_set_refs,
    _validate_string_set_local_ref,
    _validate_string_set_refs,
    infer_string_count_like,
)
from yaraast.types._registry import (
    ArrayType,
    BooleanType,
    DictionaryType,
    DoubleType,
    IntegerType,
    RangeType,
    ScalarType,
    StringIdentifierType,
    StringSetType,
    StringType,
    TypeEnvironment,
    UnknownType,
)
from yaraast.types.module_contracts import FunctionDefinition

# ---------------------------------------------------------------------------
# Minimal context helper (no mocks — TypeEnvironment + ExpressionTypeInference)
# ---------------------------------------------------------------------------


def _inference(env: TypeEnvironment | None = None) -> ExpressionTypeInference:
    return ExpressionTypeInference(env if env is not None else TypeEnvironment())


def _errors_from(node: Any, env: TypeEnvironment | None = None) -> tuple[Any, list[str]]:
    inf = _inference(env)
    result = inf.infer(node)
    return result, inf.errors


class _FakeCtx:
    """Minimal context object for testing private helper functions directly.

    Used only for helpers that accept a plain context object rather than the
    full ExpressionTypeInference.  The ``visit`` method always returns
    ``UnknownType`` so that any call chain that bottoms out into visiting an
    AST node produces a deterministic unknown result.
    """

    def __init__(self) -> None:
        self.errors: list[str] = []

    def visit(self, node: Any) -> UnknownType:
        return UnknownType()


# ===========================================================================
# Lines 90, 97-99, 103, 106-107: infer_identifier and _infer_string_reference
# ===========================================================================


def test_identifier_resolves_to_module_type_when_env_has_module() -> None:
    """Line 90: infer_identifier returns cast module type when _resolve_module_type matches."""
    env = TypeEnvironment()
    env.add_module("pe", "pe")
    result, errors = _errors_from(Identifier("pe"), env)

    assert errors == []
    # The result must be a module type, not an unknown.
    assert not isinstance(result, UnknownType)


def test_identifier_starting_with_dollar_invalid_normalisation_produces_unknown() -> None:
    """Lines 97-99: _infer_string_reference_identifier emits error on bad string ref."""
    env = TypeEnvironment()
    env.add_string("$a")
    result, errors = _errors_from(Identifier("$bad-name"), env)

    assert isinstance(result, UnknownType)
    assert any("Invalid string reference" in e for e in errors)


def test_identifier_starting_with_dollar_found_in_scope_returns_scoped_type() -> None:
    """Line 103: _infer_string_reference_identifier returns scoped type when in env."""
    env = TypeEnvironment()
    env.scopes[-1]["$a"] = StringIdentifierType()
    result, errors = _errors_from(Identifier("$a"), env)

    assert isinstance(result, StringIdentifierType)
    assert errors == []


def test_identifier_starting_with_dollar_not_defined_emits_undefined_string_error() -> None:
    """Lines 106-107: undefined string reference emits 'Undefined string' error."""
    env = TypeEnvironment()
    env.add_string("$a")
    result, errors = _errors_from(Identifier("$b"), env)

    assert isinstance(result, UnknownType)
    assert any("Undefined string: $b" in e for e in errors)


# ===========================================================================
# Line 118: infer_string_count_like with boolean occurrence index
# ===========================================================================


def test_string_count_like_with_boolean_index_emits_type_error() -> None:
    """Line 118: index validation fires when string_id matches implicit loop var."""
    env = TypeEnvironment()
    env.scopes[-1]["$"] = IntegerType()
    inf = _inference(env)

    out = infer_string_count_like(inf, "", "StringCount", index=BooleanLiteral(True))

    assert isinstance(out, IntegerType)
    assert any("index must not be boolean" in e for e in inf.errors)


# ===========================================================================
# Lines 250, 266: _is_literal_boolean_comparison_operand, _has_unknown_comparison_operand
# ===========================================================================


def test_is_literal_boolean_comparison_operand_returns_true_for_raw_bool() -> None:
    """Line 250: raw Python bool is treated as a boolean literal operand."""
    assert _is_literal_boolean_comparison_operand(True) is True
    assert _is_literal_boolean_comparison_operand(False) is True


def test_has_unknown_comparison_operand_returns_true_without_error_for_string_identifier() -> None:
    """Line 266: StringIdentifier with UnknownType returns True but emits no extra error."""
    ctx = _FakeCtx()
    result = _has_unknown_comparison_operand(
        ctx, ">", "Left", StringIdentifier("$x"), UnknownType()
    )

    assert result is True
    assert ctx.errors == []


def test_comparison_op_with_undefined_string_identifier_produces_error() -> None:
    """Line 266 via inference path: comparing undefined string identifier triggers error."""
    env = TypeEnvironment()
    result, errors = _errors_from(
        BinaryExpression(StringIdentifier("$x"), ">", IntegerLiteral(1)), env
    )

    assert isinstance(result, BooleanType)
    assert any("Undefined string" in e for e in errors)


# ===========================================================================
# Lines 311-345: _constant_integer_value
# ===========================================================================


def test_constant_integer_value_unary_non_const_operand_returns_none() -> None:
    """Line 311: UnaryExpression with non-constant operand returns None."""
    assert _constant_integer_value(UnaryExpression("-", Identifier("x"))) is None


def test_constant_integer_value_bitwise_not() -> None:
    """Line 316: UnaryExpression with '~' operator returns bitwise NOT of value."""
    assert _constant_integer_value(UnaryExpression("~", IntegerLiteral(5))) == ~5


def test_constant_integer_value_addition() -> None:
    """Line 326: BinaryExpression '+' folds constants."""
    assert _constant_integer_value(BinaryExpression(IntegerLiteral(2), "+", IntegerLiteral(3))) == 5


def test_constant_integer_value_multiplication() -> None:
    """Line 330: BinaryExpression '*' folds constants."""
    assert (
        _constant_integer_value(BinaryExpression(IntegerLiteral(3), "*", IntegerLiteral(4))) == 12
    )


def test_constant_integer_value_division_nonzero() -> None:
    """Line 332: BinaryExpression '/' with non-zero divisor folds constants."""
    assert (
        _constant_integer_value(BinaryExpression(IntegerLiteral(10), "/", IntegerLiteral(2))) == 5
    )


def test_constant_integer_value_integer_division_backslash() -> None:
    """Line 332: BinaryExpression '\\' with non-zero divisor folds constants."""
    assert (
        _constant_integer_value(BinaryExpression(IntegerLiteral(10), "\\", IntegerLiteral(3))) == 3
    )


def test_constant_integer_value_division_by_zero_returns_none() -> None:
    """Line 332: BinaryExpression '/' with zero divisor returns None."""
    assert (
        _constant_integer_value(BinaryExpression(IntegerLiteral(10), "/", IntegerLiteral(0)))
        is None
    )


def test_constant_integer_value_modulo_nonzero() -> None:
    """Line 334: BinaryExpression '%' with non-zero divisor folds constants."""
    assert (
        _constant_integer_value(BinaryExpression(IntegerLiteral(10), "%", IntegerLiteral(3))) == 1
    )


def test_constant_integer_value_modulo_by_zero_returns_none() -> None:
    """Line 334: BinaryExpression '%' with zero divisor returns None."""
    assert (
        _constant_integer_value(BinaryExpression(IntegerLiteral(10), "%", IntegerLiteral(0)))
        is None
    )


def test_constant_integer_value_bitwise_or() -> None:
    """Line 338: BinaryExpression '|' folds constants."""
    assert _constant_integer_value(BinaryExpression(IntegerLiteral(5), "|", IntegerLiteral(3))) == 7


def test_constant_integer_value_bitwise_xor() -> None:
    """Line 340: BinaryExpression '^' folds constants."""
    assert _constant_integer_value(BinaryExpression(IntegerLiteral(5), "^", IntegerLiteral(3))) == 6


def test_constant_integer_value_shift_left_negative_returns_none() -> None:
    """Line 342-343: '<<' with negative right returns None."""
    assert (
        _constant_integer_value(
            BinaryExpression(IntegerLiteral(5), "<<", UnaryExpression("-", IntegerLiteral(1)))
        )
        is None
    )


def test_constant_integer_value_shift_right_negative_returns_none() -> None:
    """Line 343-344: '>>' with negative right returns None."""
    assert (
        _constant_integer_value(BinaryExpression(IntegerLiteral(8), ">>", IntegerLiteral(-1)))
        is None
    )


def test_constant_integer_value_shift_right_positive() -> None:
    """Line 344: '>>' with positive right folds constants."""
    assert (
        _constant_integer_value(BinaryExpression(IntegerLiteral(8), ">>", IntegerLiteral(1))) == 4
    )


def test_constant_integer_value_unknown_operator_returns_none() -> None:
    """Line 345: BinaryExpression with unrecognised operator returns None."""
    assert (
        _constant_integer_value(BinaryExpression(IntegerLiteral(5), "and", IntegerLiteral(3)))
        is None
    )


# ===========================================================================
# Line 444: infer_function_call with receiver and invalid function name
# ===========================================================================


def test_function_call_invalid_name_with_receiver_visits_receiver_and_returns_unknown() -> None:
    """Line 444: when function name is invalid and receiver is present, receiver is visited."""
    env = TypeEnvironment()
    inf = _inference(env)
    fc = FunctionCall(function="bad-func", arguments=[])
    fc.receiver = IntegerLiteral(1)

    out = inf.infer(fc)

    assert isinstance(out, UnknownType)
    assert any("Invalid function identifier" in e for e in inf.errors)


# ===========================================================================
# Lines 605-610: _validate_function_argument_types with variadic FunctionDefinition
# ===========================================================================


def test_validate_function_argument_types_variadic_extra_arg_wrong_type_emits_error() -> None:
    """Lines 605-610: variadic extra arguments checked against the last parameter type."""
    func_def = FunctionDefinition(
        name="test_variadic",
        return_type=IntegerType(),
        parameters=[("value", IntegerType())],
        variadic=True,
        min_parameters=None,
    )
    inf = _inference()
    args = [IntegerLiteral(1), IntegerLiteral(2), StringLiteral("bad")]

    _validate_function_argument_types(inf, "test_variadic", func_def, args)

    assert any("must be integer, got string" in e for e in inf.errors)


def test_validate_function_argument_types_variadic_all_valid_produces_no_error() -> None:
    """Lines 605-610 (happy path): variadic arguments all matching type produce no error."""
    func_def = FunctionDefinition(
        name="test_variadic",
        return_type=IntegerType(),
        parameters=[("value", IntegerType())],
        variadic=True,
        min_parameters=None,
    )
    inf = _inference()
    args = [IntegerLiteral(1), IntegerLiteral(2), IntegerLiteral(3)]

    _validate_function_argument_types(inf, "test_variadic", func_def, args)

    assert inf.errors == []


# ===========================================================================
# Line 625: _is_function_argument_compatible with ScalarType
# ===========================================================================


def test_is_function_argument_compatible_scalar_accepts_integer() -> None:
    """Line 625: ScalarType parameter accepts integer argument."""
    assert _is_function_argument_compatible(ScalarType(), IntegerType()) is True


def test_is_function_argument_compatible_scalar_accepts_string() -> None:
    """Line 625: ScalarType parameter accepts string argument."""
    assert _is_function_argument_compatible(ScalarType(), StringType()) is True


def test_is_function_argument_compatible_scalar_accepts_double() -> None:
    """Line 625: ScalarType parameter accepts double argument."""
    assert _is_function_argument_compatible(ScalarType(), DoubleType()) is True


def test_is_function_argument_compatible_scalar_rejects_boolean() -> None:
    """Line 625: ScalarType parameter rejects boolean argument."""
    assert _is_function_argument_compatible(ScalarType(), BooleanType()) is False


# ===========================================================================
# Lines 679, 694-695: pe.exports and pe.exports_index with wrong argument count
# ===========================================================================


def test_pe_exports_wrong_argument_count_emits_error() -> None:
    """Line 679: pe.exports with 2 arguments emits count error."""
    from yaraast.parser.source import parse_yara_source
    from yaraast.types.semantic_validator import SemanticValidator

    src = 'import "pe"\nrule r { condition: pe.exports(1, 2) }'
    errors = [e.message for e in SemanticValidator().validate(parse_yara_source(src)).errors]

    assert any("'exports' expects 1 arguments, got 2" in e for e in errors)


def test_pe_exports_index_wrong_argument_count_emits_error() -> None:
    """Lines 694-695: pe.exports_index with 2 arguments emits count error."""
    from yaraast.parser.source import parse_yara_source
    from yaraast.types.semantic_validator import SemanticValidator

    src = 'import "pe"\nrule r { condition: pe.exports_index(1, 2) }'
    errors = [e.message for e in SemanticValidator().validate(parse_yara_source(src)).errors]

    assert any("'exports_index' expects 1 arguments, got 2" in e for e in errors)


# ===========================================================================
# Line 697: pe.exports accepts integer and regex argument types
# ===========================================================================


def test_pe_exports_with_integer_argument_has_no_type_error() -> None:
    """Line 697: pe.exports accepts integer ordinal argument."""
    from yaraast.parser.source import parse_yara_source
    from yaraast.types.semantic_validator import SemanticValidator

    src = 'import "pe"\nrule r { condition: pe.exports(1) }'
    errors = [e.message for e in SemanticValidator().validate(parse_yara_source(src)).errors]

    assert not any("does not accept" in e for e in errors)


def test_pe_exports_with_regex_argument_has_no_type_error() -> None:
    """Line 697: pe.exports accepts regex argument."""
    from yaraast.parser.source import parse_yara_source
    from yaraast.types.semantic_validator import SemanticValidator

    src = 'import "pe"\nrule r { condition: pe.exports(/kernel32/) }'
    errors = [e.message for e in SemanticValidator().validate(parse_yara_source(src)).errors]

    assert not any("does not accept" in e for e in errors)


# ===========================================================================
# Lines 713-714, 725-726: section_index argument count validation
# ===========================================================================


def test_pe_section_index_wrong_argument_count_emits_error() -> None:
    """Lines 713-714: pe.section_index with 2 arguments emits count error."""
    from yaraast.parser.source import parse_yara_source
    from yaraast.types.semantic_validator import SemanticValidator

    src = 'import "pe"\nrule r { condition: pe.section_index(1, 2) > 0 }'
    errors = [e.message for e in SemanticValidator().validate(parse_yara_source(src)).errors]

    assert any("'section_index' expects 1 arguments, got 2" in e for e in errors)


def test_pe_section_index_with_string_argument_has_no_error() -> None:
    """Lines 725-726: pe.section_index valid with string argument."""
    from yaraast.parser.source import parse_yara_source
    from yaraast.types.semantic_validator import SemanticValidator

    src = 'import "pe"\nrule r { condition: pe.section_index(".text") > 0 }'
    errors = [e.message for e in SemanticValidator().validate(parse_yara_source(src)).errors]

    assert not any("does not accept" in e for e in errors)


# ===========================================================================
# Line 752: pe.import_rva with unknown argument types skips type validation
# ===========================================================================


def test_validate_pe_import_rva_unknown_args_produces_no_type_error() -> None:
    """Line 752 (753->exit branch): unknown arg types in import_rva skip type checks."""
    inf = _inference()
    args = [Identifier("undefined_a"), Identifier("undefined_b")]

    _validate_pe_import_rva_arguments(inf, "import_rva", args)

    assert not any("does not accept" in e for e in inf.errors)


# ===========================================================================
# Lines 771, 786: hash and math unknown args cause early return
# ===========================================================================


def test_validate_hash_function_unknown_args_skips_type_check() -> None:
    """Line 771: when hash function args contain unknown types, no type error is emitted."""
    inf = _inference()
    args = [Identifier("undef1"), Identifier("undef2")]

    _validate_hash_function_arguments(inf, "md5", args)

    assert not any("does not accept" in e for e in inf.errors)


def test_validate_math_function_unknown_args_skips_type_check() -> None:
    """Line 786: when math function args contain unknown types, no type error is emitted."""
    inf = _inference()
    args = [Identifier("undef_offset")]

    _validate_math_function_arguments(inf, "entropy", args)

    assert not any("does not accept" in e for e in inf.errors)


# ===========================================================================
# Lines 825, 834: _matches_math_deviation_signature
# ===========================================================================


def test_math_deviation_with_three_valid_args_has_no_error() -> None:
    """Line 825: math.deviation(int, int, double) is a valid 3-argument call."""
    from yaraast.parser.source import parse_yara_source
    from yaraast.types.semantic_validator import SemanticValidator

    src = 'import "math"\nrule r { condition: math.deviation(0, filesize, 1.0) > 0.0 }'
    errors = [e.message for e in SemanticValidator().validate(parse_yara_source(src)).errors]

    assert not any("does not accept" in e for e in errors)


def test_math_deviation_with_one_arg_emits_type_error() -> None:
    """Line 834: math.deviation(int) has no valid overload and produces an error."""
    from yaraast.parser.source import parse_yara_source
    from yaraast.types.semantic_validator import SemanticValidator

    src = 'import "math"\nrule r { condition: math.deviation(0) > 0.0 }'
    errors = [e.message for e in SemanticValidator().validate(parse_yara_source(src)).errors]

    assert any("does not accept" in e for e in errors)


# ===========================================================================
# Lines 918-925: _infer_dictionary_key_type with raw Python primitives
# ===========================================================================


def test_infer_dictionary_key_type_for_bool() -> None:
    """Line 918: Python bool raw key returns BooleanType."""
    ctx = _FakeCtx()
    assert isinstance(_infer_dictionary_key_type(ctx, True), BooleanType)


def test_infer_dictionary_key_type_for_int() -> None:
    """Line 920: Python int raw key returns IntegerType."""
    ctx = _FakeCtx()
    assert isinstance(_infer_dictionary_key_type(ctx, 5), IntegerType)


def test_infer_dictionary_key_type_for_float() -> None:
    """Line 922: Python float raw key returns DoubleType."""
    ctx = _FakeCtx()
    assert isinstance(_infer_dictionary_key_type(ctx, 1.5), DoubleType)


def test_infer_dictionary_key_type_for_str() -> None:
    """Line 924: Python str raw key returns StringType."""
    ctx = _FakeCtx()
    assert isinstance(_infer_dictionary_key_type(ctx, "key"), StringType)


def test_infer_dictionary_key_type_for_unknown_object() -> None:
    """Line 925: unknown raw key returns UnknownType."""
    ctx = _FakeCtx()
    assert isinstance(_infer_dictionary_key_type(ctx, object()), UnknownType)


# ===========================================================================
# Lines 932-933: SetExpression of string set visits elements with .accept
# ===========================================================================


def test_string_set_expression_with_string_identifiers_visits_each_element() -> None:
    """Lines 932-933: SetExpression containing StringIdentifiers visits all elements."""
    env = TypeEnvironment()
    env.add_string("$a")
    env.add_string("$b")
    result, errors = _errors_from(
        SetExpression([StringIdentifier("$a"), StringIdentifier("$b")]), env
    )

    assert isinstance(result, StringSetType)
    assert errors == []


# ===========================================================================
# Line 948: _infer_set_element_type with empty elements returns UnknownType
# ===========================================================================


def test_infer_set_element_type_empty_elements_returns_unknown() -> None:
    """Line 948: empty elements list returns UnknownType."""
    inf = _inference()
    result = _infer_set_element_type(inf, [])

    assert isinstance(result, UnknownType)


# ===========================================================================
# Lines 966-967, 973-974: _is_string_set_element
# ===========================================================================


def test_is_string_set_element_wildcard_starting_with_dollar_is_true() -> None:
    """Lines 966-967: StringWildcard starting with '$' is a string set element."""
    assert _is_string_set_element(StringWildcard("$abc*")) is True


def test_is_string_set_element_wildcard_not_starting_with_dollar_is_false() -> None:
    """Line 966: StringWildcard not starting with '$' is not a string set element."""
    assert _is_string_set_element(StringWildcard("abc*")) is False


def test_is_string_set_element_identifier_them_is_true() -> None:
    """Lines 973-974: Identifier named 'them' is a valid string set element."""
    assert _is_string_set_element(Identifier("them")) is True


def test_is_string_set_element_identifier_dollar_prefixed_is_true() -> None:
    """Lines 973-974: Identifier starting with '$' is a valid string set element."""
    assert _is_string_set_element(Identifier("$a")) is True


def test_is_string_set_element_plain_identifier_is_false() -> None:
    """Line 973: Plain identifier name is not a string set element."""
    assert _is_string_set_element(Identifier("other")) is False


# ===========================================================================
# Line 1002: _infer_quantifier_value fallthrough returns UnknownType
# ===========================================================================


def test_infer_quantifier_value_unknown_object_returns_unknown() -> None:
    """Line 1002: object that matches no branch returns UnknownType."""
    ctx = _FakeCtx()
    result = _infer_quantifier_value(ctx, object())

    assert isinstance(result, UnknownType)


# ===========================================================================
# Lines 1015->1017, 1020, 1022, 1026, 1036-1037: _validate_quantifier_value
# ===========================================================================


def test_validate_quantifier_value_negative_int_emits_error() -> None:
    """Lines 1015->1017: negative raw int quantifier emits invalid quantifier error."""
    ctx = _FakeCtx()
    _validate_quantifier_value(ctx, -1, context="of", allow_percentage=False)

    assert any("Invalid of quantifier '-1'" in e for e in ctx.errors)


def test_validate_quantifier_value_float_with_percentage_allowed_valid() -> None:
    """Line 1020: valid float percentage (0 < value <= 1) produces no error."""
    ctx = _FakeCtx()
    _validate_quantifier_value(ctx, 0.5, context="of", allow_percentage=True)

    assert ctx.errors == []


def test_validate_quantifier_value_float_with_percentage_allowed_out_of_range() -> None:
    """Line 1020: float > 1 with allow_percentage=True emits range error."""
    ctx = _FakeCtx()
    _validate_quantifier_value(ctx, 1.5, context="of", allow_percentage=True)

    assert any("percentage quantifier must be between 1 and 100" in e for e in ctx.errors)


def test_validate_quantifier_value_float_without_percentage_allowed_emits_error() -> None:
    """Line 1022: float with allow_percentage=False emits invalid quantifier error."""
    ctx = _FakeCtx()
    _validate_quantifier_value(ctx, 0.5, context="for", allow_percentage=False)

    assert any("Invalid for quantifier '0.5'" in e for e in ctx.errors)


def test_validate_quantifier_value_integer_literal_negative_emits_error() -> None:
    """Line 1026: IntegerLiteral with negative value emits invalid quantifier error."""
    ctx = _FakeCtx()
    _validate_quantifier_value(ctx, IntegerLiteral(-1), context="of", allow_percentage=False)

    assert any("Invalid of quantifier '-1'" in e for e in ctx.errors)


def test_validate_quantifier_value_percent_unary_without_allow_percentage_emits_error() -> None:
    """Lines 1036-1037: UnaryExpression '%' with allow_percentage=False emits error."""
    ctx = _FakeCtx()
    _validate_quantifier_value(
        ctx, UnaryExpression("%", IntegerLiteral(50)), context="for", allow_percentage=False
    )

    assert any("Invalid for quantifier '%'" in e for e in ctx.errors)


# ===========================================================================
# Lines 1086, 1088: _has_invalid_static_percentage_operand
# ===========================================================================


def test_has_invalid_static_percentage_operand_string_literal_is_invalid() -> None:
    """Line 1086: StringLiteral operand is always invalid for a percentage expression."""
    assert _has_invalid_static_percentage_operand(StringLiteral("50")) is True


def test_has_invalid_static_percentage_operand_parenthesised_string_literal_is_invalid() -> None:
    """Line 1088: ParenthesesExpression wrapping a StringLiteral is invalid."""
    assert (
        _has_invalid_static_percentage_operand(ParenthesesExpression(StringLiteral("50"))) is True
    )


# ===========================================================================
# Lines 1100, 1108, 1112-1160: _static_integer_value
# ===========================================================================


def test_static_integer_value_raw_int_returns_value() -> None:
    """Line 1100: raw Python int returns that int."""
    assert _static_integer_value(5) == 5


def test_static_integer_value_parenthesised_integer_literal() -> None:
    """Line 1108: ParenthesesExpression containing IntegerLiteral is folded."""
    assert _static_integer_value(ParenthesesExpression(IntegerLiteral(7))) == 7


def test_static_integer_value_unary_with_non_minus_non_tilde_returns_none() -> None:
    """Lines 1112: UnaryExpression with operator other than '-'/'~' returns None."""
    assert _static_integer_value(UnaryExpression("not", IntegerLiteral(5))) is None


def test_static_integer_value_binary_addition() -> None:
    """Line 1131: BinaryExpression '+' folds constant integers."""
    assert _static_integer_value(BinaryExpression(IntegerLiteral(2), "+", IntegerLiteral(3))) == 5


def test_static_integer_value_binary_subtraction() -> None:
    """Line 1136 area: BinaryExpression '-' folds constant integers."""
    assert _static_integer_value(BinaryExpression(IntegerLiteral(5), "-", IntegerLiteral(2))) == 3


def test_static_integer_value_binary_modulo() -> None:
    """Line 1136: BinaryExpression '%' folds constant integers."""
    assert _static_integer_value(BinaryExpression(IntegerLiteral(10), "%", IntegerLiteral(3))) == 1


def test_static_integer_value_binary_modulo_by_zero_returns_none() -> None:
    """Line 1144: BinaryExpression '%' with zero divisor returns None."""
    assert (
        _static_integer_value(BinaryExpression(IntegerLiteral(10), "%", IntegerLiteral(0))) is None
    )


def test_static_integer_value_shift_left_positive() -> None:
    """Line 1138: BinaryExpression '<<' with positive shift folds."""
    assert _static_integer_value(BinaryExpression(IntegerLiteral(1), "<<", IntegerLiteral(2))) == 4


def test_static_integer_value_shift_left_negative_returns_none() -> None:
    """Line 1155: '<<' with negative right operand returns None."""
    assert (
        _static_integer_value(BinaryExpression(IntegerLiteral(5), "<<", IntegerLiteral(-1))) is None
    )


def test_static_integer_value_shift_left_64_returns_zero() -> None:
    """Lines 1156-1157: '<<' with shift >= 64 returns 0 (overflow)."""
    assert _static_integer_value(BinaryExpression(IntegerLiteral(5), "<<", IntegerLiteral(64))) == 0


def test_static_integer_value_shift_right_positive() -> None:
    """Line 1140: BinaryExpression '>>' with positive shift folds."""
    assert _static_integer_value(BinaryExpression(IntegerLiteral(8), ">>", IntegerLiteral(1))) == 4


def test_static_integer_value_bitwise_and() -> None:
    """Line 1145: BinaryExpression '&' folds constant integers."""
    assert _static_integer_value(BinaryExpression(IntegerLiteral(5), "&", IntegerLiteral(3))) == 1


def test_static_integer_value_bitwise_or() -> None:
    """Line 1149: BinaryExpression '|' folds constant integers."""
    assert _static_integer_value(BinaryExpression(IntegerLiteral(5), "|", IntegerLiteral(3))) == 7


def test_static_integer_value_bitwise_xor() -> None:
    """Line 1153: BinaryExpression '^' folds constant integers."""
    assert _static_integer_value(BinaryExpression(IntegerLiteral(5), "^", IntegerLiteral(3))) == 6


def test_static_integer_value_binary_left_unknown_shift_returns_none() -> None:
    """Lines 1158-1159: left operand unknown for '<<' returns None after right check."""
    assert _static_integer_value(BinaryExpression(Identifier("x"), "<<", IntegerLiteral(2))) is None


# ===========================================================================
# Lines 1172, 1176, 1180-1181, 1184: _validate_quantifier_text_value
# ===========================================================================


def test_validate_quantifier_text_value_any_produces_no_error() -> None:
    """Line 1172: text quantifier 'any' is valid."""
    ctx = _FakeCtx()
    _validate_quantifier_text_value(ctx, "any", context="of", allow_percentage=False)

    assert ctx.errors == []


def test_validate_quantifier_text_value_digit_string_produces_no_error() -> None:
    """Line 1176: numeric digit string quantifier is valid."""
    ctx = _FakeCtx()
    _validate_quantifier_text_value(ctx, "5", context="of", allow_percentage=False)

    assert ctx.errors == []


def test_validate_quantifier_text_value_percentage_without_allow_percentage_emits_error() -> None:
    """Line 1180: percentage text with allow_percentage=False emits error."""
    ctx = _FakeCtx()
    _validate_quantifier_text_value(ctx, "50%", context="for", allow_percentage=False)

    assert any("Invalid for quantifier '50%'" in e for e in ctx.errors)


def test_validate_quantifier_text_value_non_digit_percentage_emits_error() -> None:
    """Line 1180: non-digit percentage text emits error even if allow_percentage=True."""
    ctx = _FakeCtx()
    _validate_quantifier_text_value(ctx, "abc%", context="of", allow_percentage=True)

    assert any("Invalid of quantifier 'abc%'" in e for e in ctx.errors)


def test_validate_quantifier_text_value_valid_percentage_produces_no_error() -> None:
    """Line 1181: valid integer percentage (1-100%) produces no error."""
    ctx = _FakeCtx()
    _validate_quantifier_text_value(ctx, "50%", context="of", allow_percentage=True)

    assert ctx.errors == []


def test_validate_quantifier_text_value_zero_percentage_emits_range_error() -> None:
    """Line 1184: 0% is out of the valid range."""
    ctx = _FakeCtx()
    _validate_quantifier_text_value(ctx, "0%", context="of", allow_percentage=True)

    assert any("must be between 1 and 100" in e for e in ctx.errors)


def test_validate_quantifier_text_value_over_100_percentage_emits_range_error() -> None:
    """Line 1184: 101% exceeds the valid range."""
    ctx = _FakeCtx()
    _validate_quantifier_text_value(ctx, "101%", context="of", allow_percentage=True)

    assert any("must be between 1 and 100" in e for e in ctx.errors)


# ===========================================================================
# Line 1219: _infer_string_set_value with list/frozenset
# ===========================================================================


def test_infer_string_set_value_with_list_returns_string_set_type() -> None:
    """Line 1219: a Python list passed as string set value returns StringSetType."""
    ctx = _FakeCtx()
    result = _infer_string_set_value(ctx, ["$a", "$b"])

    assert isinstance(result, StringSetType)


def test_infer_string_set_value_with_frozenset_returns_string_set_type() -> None:
    """Line 1219: a Python frozenset passed as string set value returns StringSetType."""
    ctx = _FakeCtx()
    result = _infer_string_set_value(ctx, frozenset(["$a"]))

    assert isinstance(result, StringSetType)


# ===========================================================================
# Lines 1250-1251: _lookup_string_set_local with non-string name
# ===========================================================================


def test_lookup_string_set_local_non_string_name_emits_error_and_returns_none() -> None:
    """Lines 1250-1251: non-string name triggers 'must be a string' error."""
    inf = _inference()
    result = _lookup_string_set_local(inf, cast(Any, 123))

    assert result is None
    assert any("must be a string" in e for e in inf.errors)


# ===========================================================================
# Line 1268: _validate_string_set_local_ref with wrong local type
# ===========================================================================


def test_validate_string_set_local_ref_wrong_type_emits_error_and_returns_true() -> None:
    """Line 1268: local variable with wrong type emits error but still returns True."""
    env = TypeEnvironment()
    env.scopes[-1]["myvar"] = IntegerType()
    inf = _inference(env)

    result = _validate_string_set_local_ref(inf, "myvar")

    assert result is True
    assert any("must be string or string set" in e for e in inf.errors)


# ===========================================================================
# Line 1277: _validate_string_set_refs with list
# ===========================================================================


def test_validate_string_set_refs_with_list_validates_each_item() -> None:
    """Line 1277: list of string refs is validated element-by-element."""
    env = TypeEnvironment()
    env.add_string("$a")
    inf = _inference(env)

    _validate_string_set_refs(inf, ["$a"])

    assert inf.errors == []


# ===========================================================================
# Lines 1323: _validate_string_set_refs with Identifier starting with '$'
# ===========================================================================


def test_validate_string_set_refs_dollar_identifier_looks_up_raw_string() -> None:
    """Lines 1321-1327: Identifier starting with '$' validates as a raw string ref."""
    env = TypeEnvironment()
    env.add_string("$a")
    inf = _inference(env)

    _validate_string_set_refs(inf, Identifier("$a"))

    assert inf.errors == []


def test_validate_string_set_refs_dollar_identifier_undefined_emits_error() -> None:
    """Line 1324: '$'-prefixed Identifier not in env emits 'Undefined string' error."""
    env = TypeEnvironment()
    env.add_string("$a")
    inf = _inference(env)

    _validate_string_set_refs(inf, Identifier("$nonexistent"))

    assert any("Undefined string" in e for e in inf.errors)


# ===========================================================================
# Line 1332->exit: _validate_string_set_refs with node that has .accept
# ===========================================================================


def test_validate_string_set_refs_with_accept_node_visits_it() -> None:
    """Line 1332: node that has .accept attribute is visited via ctx.visit."""
    env = TypeEnvironment()
    inf = _inference(env)

    _validate_string_set_refs(inf, DoubleLiteral(1.0))

    assert inf.errors == []


# ===========================================================================
# Lines 1359-1361: _classify_of_set_value with list/tuple/frozenset
# ===========================================================================


def test_classify_of_set_value_list_of_string_elements_returns_string() -> None:
    """Line 1359: list of string set elements classifies as 'string'."""
    assert _classify_of_set_value([Identifier("$a"), Identifier("$b")]) == "string"


def test_classify_of_set_value_mixed_list_returns_mixed() -> None:
    """Line 1360: list with both string and rule elements classifies as 'mixed'."""
    assert _classify_of_set_value([Identifier("$a"), Identifier("rule_name")]) == "mixed"


def test_classify_of_set_value_non_set_non_rule_returns_none() -> None:
    """Line 1361: element that is neither string nor rule returns None."""
    assert _classify_of_set_value(IntegerLiteral(1)) is None


# ===========================================================================
# Lines 1399-1401: _validate_rule_set_refs with list
# ===========================================================================


def test_validate_rule_set_refs_list_with_undefined_rule_emits_error() -> None:
    """Lines 1399-1401: list containing an undefined rule emits 'Undefined rule' error."""
    env = TypeEnvironment()
    env.add_rule("existing_rule")
    inf = _inference(env)

    _validate_rule_set_refs(inf, [Identifier("existing_rule"), Identifier("missing_rule")])

    assert any("Undefined rule: missing_rule" in e for e in inf.errors)
    assert not any("Undefined rule: existing_rule" in e for e in inf.errors)


# ===========================================================================
# Lines 1405-1406: _validate_rule_set_refs with non-string Identifier name
# ===========================================================================


def test_validate_rule_set_refs_non_string_identifier_name_emits_error() -> None:
    """Lines 1405-1406: Identifier with non-string name emits 'must be a string' error."""
    inf = _inference()

    _validate_rule_set_refs(inf, Identifier(cast(Any, 123)))

    assert any("Rule reference must be a string" in e for e in inf.errors)


# ===========================================================================
# Lines 1451-1455: _define_for_iteration_variables RangeType with >1 variable
# ===========================================================================


def test_define_for_iteration_variables_range_two_vars_emits_error() -> None:
    """Lines 1451-1454: RangeType with 2 loop variables emits unpack error."""
    env = TypeEnvironment()
    env.push_scope()
    inf = _inference(env)

    _define_for_iteration_variables(inf, ["x", "y"], RangeType())

    assert any("Cannot unpack 2 loop variables from type: range" in e for e in inf.errors)


# ===========================================================================
# Lines 1469-1470: _define_for_iteration_variables ArrayType with >1 variable
# ===========================================================================


def test_define_for_iteration_variables_array_two_vars_emits_error() -> None:
    """Lines 1469-1470: ArrayType with 2 loop variables emits unpack error."""
    env = TypeEnvironment()
    env.push_scope()
    inf = _inference(env)

    _define_for_iteration_variables(inf, ["x", "y"], ArrayType(IntegerType()))

    assert any("Cannot unpack 2 loop variables from type: array[integer]" in e for e in inf.errors)


# ===========================================================================
# Lines 1472-1479: DictionaryType iteration variable cases
# ===========================================================================


def test_define_for_iteration_variables_dict_one_var_defines_key_type() -> None:
    """Line 1469 area: DictionaryType with 1 variable binds the key type."""
    env = TypeEnvironment()
    env.push_scope()
    inf = _inference(env)

    _define_for_iteration_variables(inf, ["k"], DictionaryType(StringType(), IntegerType()))

    assert inf.errors == []
    assert isinstance(env.lookup("k"), StringType)


def test_define_for_iteration_variables_dict_two_vars_defines_key_and_value() -> None:
    """Lines 1472-1473: DictionaryType with 2 variables binds key and value types."""
    env = TypeEnvironment()
    env.push_scope()
    inf = _inference(env)

    _define_for_iteration_variables(inf, ["k", "v"], DictionaryType(StringType(), IntegerType()))

    assert inf.errors == []
    assert isinstance(env.lookup("k"), StringType)
    assert isinstance(env.lookup("v"), IntegerType)


def test_define_for_iteration_variables_dict_three_vars_emits_error() -> None:
    """Lines 1475-1478: DictionaryType with 3 loop variables emits unpack error."""
    env = TypeEnvironment()
    env.push_scope()
    inf = _inference(env)

    _define_for_iteration_variables(
        inf, ["a", "b", "c"], DictionaryType(StringType(), IntegerType())
    )

    assert any(
        "Cannot unpack 3 loop variables from type: dict[string, integer]" in e for e in inf.errors
    )


# ===========================================================================
# Line 1528: ForExpression loop variable shadows a string identifier
# ===========================================================================


def test_for_expression_variable_shadowing_string_emits_shadow_warning() -> None:
    """Line 1536 (body of for-expression body type check / shadow check): variable
    whose name matches a defined string emits a shadow error."""
    env = TypeEnvironment()
    env.add_string("$loop")
    result, errors = _errors_from(
        ForExpression(
            quantifier="any",
            variable="loop",
            iterable=SetExpression([IntegerLiteral(1), IntegerLiteral(2)]),
            body=BooleanLiteral(True),
        ),
        env,
    )

    assert isinstance(result, BooleanType)
    assert any("shadows a defined string identifier" in e for e in errors)


# ===========================================================================
# Line 1568: OfExpression else branch (set kind is None)
# ===========================================================================


def test_of_expression_with_non_set_element_triggers_else_error() -> None:
    """Line 1568: OfExpression with set_kind=None emits 'requires string set or rule set' error."""
    result, errors = _errors_from(OfExpression(quantifier="any", string_set=IntegerLiteral(1)))

    assert isinstance(result, BooleanType)
    assert any("requires string set or rule set" in e for e in errors)


# ===========================================================================
# Line 1589: ForExpression body returns non-condition type
# ===========================================================================


def test_for_expression_body_returning_array_type_emits_error() -> None:
    """Line 1589: for-loop body that returns array type emits 'must return scalar condition' error."""
    result, errors = _errors_from(
        ForExpression(
            quantifier="any",
            variable="i",
            iterable=SetExpression([IntegerLiteral(1)]),
            body=SetExpression([IntegerLiteral(1)]),
        )
    )

    assert isinstance(result, BooleanType)
    assert any("must return scalar condition" in e for e in errors)


# ===========================================================================
# Lines 1620-1628: ForOfExpression (condition=None) with rule/mixed/else sets
# ===========================================================================


def test_for_of_expression_condition_none_rule_set_validates_rules() -> None:
    """Line 1622: ForOfExpression(condition=None) with rule set validates rule references."""
    env = TypeEnvironment()
    env.add_rule("some_rule")
    result, errors = _errors_from(
        ForOfExpression(
            quantifier="any",
            string_set=Identifier("some_rule"),
            condition=None,
        ),
        env,
    )

    assert isinstance(result, BooleanType)
    assert errors == []


def test_for_of_expression_condition_none_mixed_set_emits_error() -> None:
    """Lines 1623-1624: ForOfExpression(condition=None) with mixed set emits 'mixed set' error."""
    env = TypeEnvironment()
    env.add_rule("rule1")
    env.add_string("$a")
    result, errors = _errors_from(
        ForOfExpression(
            quantifier="any",
            string_set=SetExpression([Identifier("$a"), Identifier("rule1")]),
            condition=None,
        ),
        env,
    )

    assert isinstance(result, BooleanType)
    assert any("requires string set or rule set, got mixed set" in e for e in errors)


def test_for_of_expression_condition_none_else_branch_emits_error() -> None:
    """Lines 1626-1628: ForOfExpression(condition=None) set_kind=None triggers else error."""
    result, errors = _errors_from(
        ForOfExpression(
            quantifier="any",
            string_set=IntegerLiteral(1),
            condition=None,
        )
    )

    assert isinstance(result, BooleanType)
    assert any("requires string set or rule set" in e for e in errors)


# ===========================================================================
# Lines 1623-1628: ForOfExpression (condition not None) with rule/else sets
# ===========================================================================


def test_for_of_expression_condition_not_none_rule_set_emits_string_set_error() -> None:
    """Lines 1626-1628: for...of condition with rule set emits 'for...of requires string set' error."""
    env = TypeEnvironment()
    env.add_rule("existing_rule")
    result, errors = _errors_from(
        ForOfExpression(
            quantifier="any",
            string_set=Identifier("existing_rule"),
            condition=BooleanLiteral(True),
        ),
        env,
    )

    assert isinstance(result, BooleanType)
    assert any("'for...of' requires string set" in e for e in errors)


def test_for_of_expression_condition_not_none_else_branch_emits_error() -> None:
    """Lines 1623-1624: for...of condition with non-set value emits 'for...of requires' error."""
    result, errors = _errors_from(
        ForOfExpression(
            quantifier="any",
            string_set=IntegerLiteral(1),
            condition=BooleanLiteral(True),
        )
    )

    assert isinstance(result, BooleanType)
    assert any("'for...of' requires string set" in e for e in errors)


# ===========================================================================
# Line 1634->1643: ForOfExpression condition returning non-condition type
# ===========================================================================


def test_for_of_expression_condition_returning_array_emits_scalar_error() -> None:
    """Line 1634->1643: for...of condition returning array type emits scalar error."""
    env = TypeEnvironment()
    env.add_string("$a")
    result, errors = _errors_from(
        ForOfExpression(
            quantifier="any",
            string_set=Identifier("them"),
            condition=SetExpression([IntegerLiteral(1)]),
        ),
        env,
    )

    assert isinstance(result, BooleanType)
    assert any("'for...of' condition must be scalar condition" in e for e in errors)


# ===========================================================================
# Lines 1658, 1666, 1668: _is_percentage_quantifier_value and restricted of
# ===========================================================================


def test_at_expression_with_percentage_of_expression_emits_restriction_error() -> None:
    """Line 1658: AtExpression with percentage OfExpression emits restriction error."""
    env = TypeEnvironment()
    env.add_string("$a")
    result, errors = _errors_from(
        AtExpression(
            string_id=OfExpression(
                quantifier=DoubleLiteral(0.5),
                string_set=Identifier("them"),
            ),
            offset=IntegerLiteral(0),
        ),
        env,
    )

    assert isinstance(result, BooleanType)
    assert any("Percentage of-expressions do not support" in e for e in errors)


def test_is_percentage_quantifier_value_string_ending_with_percent_is_true() -> None:
    """Line 1666: string ending in '%' is treated as percentage."""
    assert _is_percentage_quantifier_value("50%") is True


def test_is_percentage_quantifier_value_string_without_percent_is_false() -> None:
    """Line 1666: string without '%' is not a percentage."""
    assert _is_percentage_quantifier_value("50") is False


def test_is_percentage_quantifier_value_unary_percent_expression_is_true() -> None:
    """Line 1668: UnaryExpression with '%' operator is a percentage quantifier."""
    assert _is_percentage_quantifier_value(UnaryExpression("%", IntegerLiteral(50))) is True


def test_is_percentage_quantifier_value_parenthesised_percent_expression_is_true() -> None:
    """Line 1668: ParenthesesExpression wrapping a '%' UnaryExpression is a percentage."""
    assert (
        _is_percentage_quantifier_value(
            ParenthesesExpression(UnaryExpression("%", IntegerLiteral(50)))
        )
        is True
    )


def test_is_percentage_quantifier_value_string_literal_ending_with_percent_is_true() -> None:
    """Line 1664: StringLiteral whose value ends with '%' is a percentage quantifier."""
    assert _is_percentage_quantifier_value(StringLiteral("50%")) is True


def test_is_percentage_quantifier_value_string_literal_without_percent_is_false() -> None:
    """Line 1664: StringLiteral whose value does not end with '%' is not a percentage."""
    assert _is_percentage_quantifier_value(StringLiteral("50")) is False


# ===========================================================================
# Line 1653-1654: rule sets cannot use at/in restrictions
# ===========================================================================


def test_at_expression_with_rule_set_of_expression_emits_restriction_error() -> None:
    """Lines 1653-1654: AtExpression with rule-set OfExpression emits at/in restriction error."""
    env = TypeEnvironment()
    env.add_rule("some_rule")
    result, errors = _errors_from(
        AtExpression(
            string_id=OfExpression(
                quantifier="any",
                string_set=Identifier("some_rule"),
            ),
            offset=IntegerLiteral(0),
        ),
        env,
    )

    assert isinstance(result, BooleanType)
    assert any("Rule sets cannot use at/in restrictions" in e for e in errors)


# ===========================================================================
# Dictionary access edge cases (lines 907-908, 910-911)
# ===========================================================================


def test_dictionary_access_wrong_key_type_emits_type_mismatch_error() -> None:
    """Lines 907-908: DictionaryAccess with integer key on string-keyed dict emits error."""
    env = TypeEnvironment()
    env.scopes[-1]["mydict"] = DictionaryType(StringType(), IntegerType())
    result, errors = _errors_from(
        DictionaryAccess(object=Identifier("mydict"), key=IntegerLiteral(1)), env
    )

    assert isinstance(result, IntegerType)
    assert any("Dictionary key must be string, got integer" in e for e in errors)


def test_dictionary_access_on_non_dict_type_emits_error() -> None:
    """Lines 910-911: DictionaryAccess on a non-dict type emits 'non-dict type' error."""
    env = TypeEnvironment()
    env.scopes[-1]["mystr"] = StringType()
    result, errors = _errors_from(
        DictionaryAccess(object=Identifier("mystr"), key=StringLiteral("key")), env
    )

    assert isinstance(result, UnknownType)
    assert any("Cannot access dictionary on non-dict type" in e for e in errors)


# ===========================================================================
# Miscellaneous: range bounds non-integer type errors
# ===========================================================================


def test_range_low_bound_non_integer_emits_error() -> None:
    """Line 939 area: RangeExpression with non-integer low bound emits error."""
    _, errors = _errors_from(RangeExpression(StringLiteral("a"), IntegerLiteral(10)))

    assert any("Range low bound must be integer" in e for e in errors)


def test_range_high_bound_non_integer_emits_error() -> None:
    """Line 942 area: RangeExpression with non-integer high bound emits error."""
    _, errors = _errors_from(RangeExpression(IntegerLiteral(0), StringLiteral("b")))

    assert any("Range high bound must be integer" in e for e in errors)


# ===========================================================================
# Incompatible set elements
# ===========================================================================


def test_set_expression_with_incompatible_element_types_emits_error() -> None:
    """Lines 953-954: SetExpression containing integer and string emits incompatibility error."""
    _, errors = _errors_from(SetExpression([IntegerLiteral(1), StringLiteral("x")]))

    assert any("Set elements must have same type" in e for e in errors)
