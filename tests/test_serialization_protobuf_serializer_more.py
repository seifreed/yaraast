"""Extra tests for Protobuf serializer (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Identifier,
    IntegerLiteral,
    StringCount,
    StringIdentifier,
    StringLiteral,
    UnaryExpression,
)
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.serialization.protobuf_serializer import ProtobufSerializer


def _sample_ast() -> YaraFile:
    strings = [
        PlainString(
            identifier="$a",
            value="alpha",
            modifiers=[StringModifier.from_name_value("ascii")],
        ),
        HexString(
            identifier="$b",
            tokens=[
                HexByte(value=0x90),
                HexWildcard(),
                HexJump(min_jump=1, max_jump=3),
                HexNibble(high=True, value=0xA),
            ],
            modifiers=[StringModifier.from_name_value("wide")],
        ),
        RegexString(identifier="$c", regex="abc.*", modifiers=[]),
    ]
    condition = BinaryExpression(
        left=UnaryExpression(operator="not", operand=BooleanLiteral(value=False)),
        operator="and",
        right=BinaryExpression(
            left=StringCount(string_id="$a"),
            operator=">",
            right=IntegerLiteral(value=0),
        ),
    )
    rule = Rule(
        name="rule_one",
        modifiers=["private"],
        tags=[Tag(name="tag1")],
        meta={"author": "me", "score": 3},
        strings=strings,
        condition=condition,
    )
    return YaraFile(
        imports=[Import(module="pe")],
        includes=[Include(path="inc.yar")],
        rules=[rule],
    )


def test_protobuf_serializer_roundtrip_and_metadata() -> None:
    serializer = ProtobufSerializer(include_metadata=True)
    ast = _sample_ast()

    data = serializer.serialize(ast)
    assert isinstance(data, bytes) and data

    text = serializer.serialize_text(ast)
    assert "metadata" in text or "format" in text

    restored = serializer.deserialize(binary_data=data)
    assert restored.rules[0].name == "rule_one"
    assert restored.rules[0].condition is not None  # Condition is preserved (no longer placeholder)


def test_protobuf_serializer_without_metadata() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = _sample_ast()
    text = serializer.serialize_text(ast)
    assert "format" not in text


def test_protobuf_expression_conversion_paths() -> None:
    pytest.importorskip("yaraast.serialization.yara_ast_pb2")
    from yaraast.serialization import yara_ast_pb2

    serializer = ProtobufSerializer()

    expr_cases = [
        (Identifier(name="id"), lambda pb: pb.identifier.name == "id"),
        (StringIdentifier(name="$a"), lambda pb: pb.string_identifier.name == "$a"),
        (StringCount(string_id="$b"), lambda pb: pb.string_count.string_id == "$b"),
        (IntegerLiteral(value=7), lambda pb: pb.integer_literal.value == 7),
        (DoubleLiteral(value=1.5), lambda pb: pb.double_literal.value == 1.5),
        (StringLiteral(value="hi"), lambda pb: pb.string_literal.value == "hi"),
        (BooleanLiteral(value=True), lambda pb: pb.boolean_literal.value is True),
        (
            BinaryExpression(
                left=IntegerLiteral(value=1),
                operator="==",
                right=IntegerLiteral(value=2),
            ),
            lambda pb: pb.binary_expression.operator == "=="
            and pb.binary_expression.left.integer_literal.value == 1
            and pb.binary_expression.right.integer_literal.value == 2,
        ),
        (
            UnaryExpression(operator="not", operand=BooleanLiteral(value=False)),
            lambda pb: pb.unary_expression.operator == "not"
            and pb.unary_expression.operand.boolean_literal.value is False,
        ),
    ]

    for expr, predicate in expr_cases:
        pb_expr = yara_ast_pb2.Expression()
        serializer._convert_expression_to_protobuf(expr, pb_expr)
        assert predicate(pb_expr)
