"""Unsigned 64-bit integer support across YARA-X parsing and serialization."""

from __future__ import annotations

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    IntegerLiteral,
    UnaryExpression,
    _constant_range_integer_value,
)
from yaraast.codegen.generator import CodeGenerator
from yaraast.lexer.lexer_errors import LexerError
from yaraast.parser import Parser
from yaraast.serialization.protobuf_serializer import ProtobufSerializer
from yaraast.types import TypeChecker
from yaraast.types._expr_inference_ops import _constant_integer_value, _static_integer_value
from yaraast.yarax.generator import YaraXGenerator
from yaraast.yarax.parser import YaraXParser

UINT64_MAX = (1 << 64) - 1


def _left_integer(ast: YaraFile) -> int:
    condition = ast.rules[0].condition
    assert isinstance(condition, BinaryExpression)
    assert isinstance(condition.left, IntegerLiteral)
    return condition.left.value


@pytest.mark.parametrize(
    "literal",
    [str(UINT64_MAX), f"0x{UINT64_MAX:x}", f"0o{UINT64_MAX:o}"],
)
def test_yarax_parser_and_generator_preserve_uint64_max(literal: str) -> None:
    ast = YaraXParser(f"rule unsigned_max {{ condition: {literal} > 0 }}").parse()

    assert _left_integer(ast) == UINT64_MAX
    assert TypeChecker().check(ast) == []

    generated = YaraXGenerator().generate(ast)
    assert str(UINT64_MAX) in generated
    assert _left_integer(YaraXParser(generated).parse()) == UINT64_MAX


def test_classic_parser_still_rejects_values_above_int64() -> None:
    with pytest.raises(LexerError, match="Integer literal exceeds int64 maximum"):
        Parser(f"rule too_large {{ condition: {1 << 63} > 0 }}")


def test_yarax_parser_rejects_values_above_uint64() -> None:
    with pytest.raises(LexerError, match="Integer literal exceeds uint64 maximum"):
        YaraXParser(f"rule too_large {{ condition: {UINT64_MAX + 1} > 0 }}")


def test_integer_literal_ast_accepts_uint64() -> None:
    IntegerLiteral(UINT64_MAX).validate_structure()


def test_static_analysis_does_not_signed_wrap_uint64_operands() -> None:
    expressions = [
        BinaryExpression(
            left=IntegerLiteral(UINT64_MAX),
            operator="+",
            right=IntegerLiteral(1),
        ),
        UnaryExpression(operator="~", operand=IntegerLiteral(UINT64_MAX)),
    ]

    for expression in expressions:
        assert _constant_range_integer_value(expression) is None
        assert _constant_integer_value(expression) is None
        assert _static_integer_value(expression) is None
        assert YaraXParser("")._static_integer_value(expression) is None


def test_protobuf_round_trip_preserves_unsigned_integer_literal() -> None:
    ast = YaraXParser(f"rule unsigned_max {{ condition: {UINT64_MAX} == 0 }}").parse()
    serializer = ProtobufSerializer()

    protobuf_ast = serializer._ast_to_protobuf(ast)
    protobuf_literal = protobuf_ast.rules[0].condition.binary_expression.left.integer_literal
    assert protobuf_literal.HasField("unsigned_value")
    assert protobuf_literal.unsigned_value == UINT64_MAX

    restored = serializer.deserialize(serializer.serialize(ast))
    assert _left_integer(restored) == UINT64_MAX


def test_protobuf_signed_literal_field_remains_readable() -> None:
    ast = Parser("rule signed { condition: 42 == 0 }").parse()
    serializer = ProtobufSerializer()

    protobuf_ast = serializer._ast_to_protobuf(ast)
    protobuf_literal = protobuf_ast.rules[0].condition.binary_expression.left.integer_literal
    assert protobuf_literal.value == 42
    assert not protobuf_literal.HasField("unsigned_value")
    assert _left_integer(serializer.deserialize(serializer.serialize(ast))) == 42


def test_classic_generator_still_rejects_unsigned_integer_literal() -> None:
    ast = YaraXParser(f"rule unsigned_max {{ condition: {UINT64_MAX} > 0 }}").parse()

    with pytest.raises(ValueError, match="outside libyara range"):
        CodeGenerator().generate(ast)
