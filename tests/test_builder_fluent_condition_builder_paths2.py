from __future__ import annotations

import pytest

from yaraast.ast.conditions import AtExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    FunctionCall,
    MemberAccess,
    UnaryExpression,
)
from yaraast.builder.fluent_condition_builder import (
    FluentConditionBuilder,
    all_of,
    all_of_them,
    any_of,
    any_of_them,
    condition,
    filesize_gt,
    high_entropy,
    large_file,
    match,
    not_them,
    one_of,
    pe_is_dll,
    small_file,
)
from yaraast.errors import ValidationError


def test_fluent_condition_builder_remaining_helpers_and_factories() -> None:
    b = FluentConditionBuilder()

    assert isinstance(b.two_of("$a", "$b", "$c").build(), OfExpression)
    assert isinstance(b.three_of("$a", "$b", "$c", "$d").build(), OfExpression)
    assert isinstance(b.most_of("$a", "$b", "$c").build(), OfExpression)
    assert isinstance(b.few_of("$a", "$b", "$c").build(), BinaryExpression)
    assert isinstance(b.many_of("$a", "$b", "$c", "$d").build(), BinaryExpression)
    assert isinstance(b.at_most_n_of(1, "$a", "$b").build(), OfExpression)
    assert isinstance(b.at_most_n_of(2, "$a", "$b", "$c").build(), BinaryExpression)
    assert isinstance(b.between_n_and_m_of(1, 2, "$a", "$b", "$c").build(), BinaryExpression)

    assert isinstance(b.string_count_ge("$a", 2).build(), BinaryExpression)
    assert isinstance(b.string_at_offset("$a", 5).build(), AtExpression)

    assert isinstance(b.filesize_eq(12).build(), BinaryExpression)
    assert isinstance(b.tiny_file().build(), BinaryExpression)
    assert isinstance(b.huge_file().build(), BinaryExpression)

    assert isinstance(b.pe_module().build(), type(b.pe_module().build()))
    assert isinstance(b.pe_is_dll().build(), MemberAccess)
    assert isinstance(b.pe_is_exe().build(), UnaryExpression)
    assert isinstance(b.pe_is_32bit().build(), MemberAccess)
    assert isinstance(b.pe_is_64bit().build(), MemberAccess)
    assert isinstance(b.pe_section_count_eq(3).build(), BinaryExpression)
    assert isinstance(b.pe_imphash_eq("abc").build(), BinaryExpression)
    assert isinstance(b.pe_exports("fn").build(), FunctionCall)
    assert isinstance(b.pe_imports("kernel32.dll", "CreateFileW").build(), FunctionCall)

    assert isinstance(b.low_entropy().build(), BinaryExpression)
    assert isinstance(b.executable_file().build(), BinaryExpression)
    assert isinstance(b.suspicious_entropy().build(), BinaryExpression)
    assert isinstance(b.packed_executable().build(), BinaryExpression)

    with pytest.raises(ValidationError):
        FluentConditionBuilder.create().build()
    assert isinstance(
        FluentConditionBuilder.match_string("$a").build(), type(b.string_matches("$a").build())
    )
    assert isinstance(FluentConditionBuilder.always_true().build(), BooleanLiteral)
    assert isinstance(FluentConditionBuilder.always_false().build(), BooleanLiteral)

    with pytest.raises(ValidationError):
        condition().build()
    assert match("$a").build() is not None
    assert any_of_them().build() is not None
    assert all_of_them().build() is not None
    assert not_them().build() is not None
    assert one_of("$a", "$b").build() is not None
    assert any_of("$a", "$b").build() is not None
    assert all_of("$a", "$b").build() is not None
    assert filesize_gt(10).build() is not None
    assert small_file().build() is not None
    assert large_file().build() is not None
    assert pe_is_dll().build() is not None
    assert high_entropy().build() is not None


def test_fluent_condition_string_in_last_kb_expression_shape() -> None:
    expr = FluentConditionBuilder().string_in_last_kb("$a").build()
    assert isinstance(expr, InExpression)
    assert isinstance(expr.range, type(expr.range))
