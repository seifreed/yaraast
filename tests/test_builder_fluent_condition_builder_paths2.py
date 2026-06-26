from __future__ import annotations

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import AtExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    FunctionCall,
    Identifier,
    UnaryExpression,
)
from yaraast.ast.rules import Import, Rule
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.fluent_condition_builder import (
    FluentConditionBuilder,
)
from yaraast.errors import ValidationError
from yaraast.libyara.compiler import YARA_AVAILABLE, LibyaraCompiler


def test_fluent_condition_builder_remaining_helpers_and_factories() -> None:
    b = FluentConditionBuilder()

    assert isinstance(b.two_of("$a", "$b", "$c").build(), BinaryExpression)
    assert isinstance(b.three_of("$a", "$b", "$c", "$d").build(), BinaryExpression)
    assert isinstance(b.at_least_n_of(2, "$a", "$b", "$c").build(), OfExpression)
    assert isinstance(b.n_of(2, "$a", "$b", "$c").build(), OfExpression)
    assert isinstance(b.at_most_n_of(1, "$a", "$b").build(), UnaryExpression)
    assert isinstance(b.at_most_n_of(2, "$a", "$b", "$c").build(), UnaryExpression)
    assert isinstance(b.between_n_and_m_of(1, 2, "$a", "$b", "$c").build(), BinaryExpression)

    assert isinstance(b.string_count_ge("$a", 2).build(), BinaryExpression)
    assert isinstance(b.string_at_offset("$a", 5).build(), AtExpression)

    assert isinstance(b.filesize_eq(12).build(), BinaryExpression)
    assert isinstance(b.filesize_lt(1024).build(), BinaryExpression)
    assert isinstance(b.filesize_gt(100 * 1024 * 1024).build(), BinaryExpression)

    assert isinstance(b.identifier("pe").build(), Identifier)
    pe_dll = b.pe_is_dll().build()
    assert isinstance(pe_dll, FunctionCall)
    assert pe_dll.function == "pe.is_dll"
    assert pe_dll.arguments == []
    assert isinstance(b.pe_is_exe().build(), UnaryExpression)
    pe_32bit = FluentConditionBuilder(FunctionCall(function="pe.is_32bit", arguments=[])).build()
    assert isinstance(pe_32bit, FunctionCall)
    assert pe_32bit.function == "pe.is_32bit"
    assert pe_32bit.arguments == []
    pe_64bit = FluentConditionBuilder(FunctionCall(function="pe.is_64bit", arguments=[])).build()
    assert isinstance(pe_64bit, FunctionCall)
    assert pe_64bit.function == "pe.is_64bit"
    assert pe_64bit.arguments == []
    assert isinstance(b.pe_section_count_eq(3).build(), BinaryExpression)

    with pytest.raises(ValidationError):
        FluentConditionBuilder().build()
    assert isinstance(
        FluentConditionBuilder.match_string("$a").build(), type(b.string_matches("$a").build())
    )
    assert isinstance(FluentConditionBuilder.always_true().build(), BooleanLiteral)

    with pytest.raises(ValidationError):
        FluentConditionBuilder().build()
    assert FluentConditionBuilder.match_string("$a").build() is not None
    assert ConditionBuilder().any_of("them").build() is not None
    assert ConditionBuilder().all_of("them").build() is not None
    assert ConditionBuilder().any_of("them").not_().build() is not None
    assert b.one_of("$a", "$b").build() is not None
    assert b.any_of("$a", "$b").build() is not None
    assert b.all_of("$a", "$b").build() is not None
    assert b.filesize_gt(10).build() is not None
    assert b.filesize_lt(1024 * 1024).build() is not None
    assert b.large_file().build() is not None
    assert b.pe_is_dll().build() is not None
    assert b.high_entropy().build() is not None


def test_fluent_condition_string_in_last_kb_expression_shape() -> None:
    expr = FluentConditionBuilder().string_in_last_kb("$a").build()
    assert isinstance(expr, InExpression)
    assert isinstance(expr.range, type(expr.range))


@pytest.mark.parametrize("identifier", ["$bad-key", "$bad space", "$", ""])
def test_fluent_condition_builder_rejects_invalid_string_references(identifier: str) -> None:
    with pytest.raises(ValidationError, match="Invalid string reference"):
        FluentConditionBuilder.match_string(identifier)

    with pytest.raises(ValidationError, match="Invalid string reference"):
        FluentConditionBuilder().one_of("$a", identifier)

    with pytest.raises(ValidationError, match="Invalid string reference"):
        FluentConditionBuilder().string_at_offset(identifier, 0)


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python is not installed")
def test_pe_predicate_helpers_generate_libyara_compatible_calls() -> None:
    condition_expr = (
        FluentConditionBuilder()
        .pe_is_dll()
        .or_(FluentConditionBuilder(FunctionCall(function="pe.is_32bit", arguments=[])))
        .or_(FluentConditionBuilder(FunctionCall(function="pe.is_64bit", arguments=[])))
        .build()
    )
    yara_file = YaraFile(
        imports=[Import("pe")],
        rules=[Rule(name="pe_predicates", condition=condition_expr)],
    )

    result = LibyaraCompiler().compile_ast(yara_file)

    assert result.success, result.source_code
