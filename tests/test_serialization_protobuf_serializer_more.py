"""Extra tests for Protobuf serializer (no mocks)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from yaraast.ast.base import YaraFile
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
    UnaryExpression,
)
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.serialization import yara_ast_pb2
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


def test_protobuf_serializer_preserves_hex_jump_zero_and_open_bounds() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    expected_jumps = [
        (0, 100),
        (None, None),
        (0, 0),
        (None, 8),
        (4, None),
    ]
    ast = YaraFile(
        rules=[
            Rule(
                name="jump_bounds",
                strings=[
                    HexString(
                        identifier="$h",
                        tokens=[
                            HexJump(min_jump=min_jump, max_jump=max_jump)
                            for min_jump, max_jump in expected_jumps
                        ],
                    )
                ],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    string_def = restored.rules[0].strings[0]

    assert isinstance(string_def, HexString)
    assert [(token.min_jump, token.max_jump) for token in string_def.tokens] == expected_jumps


def test_protobuf_serializer_preserves_hex_alternatives() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    alternative = HexAlternative(
        alternatives=[
            [HexByte(value=0xAA), HexWildcard()],
            [HexJump(min_jump=1, max_jump=3), HexNibble(high=False, value=0xF)],
        ]
    )
    ast = YaraFile(
        rules=[
            Rule(
                name="hex_alternative",
                strings=[HexString(identifier="$h", tokens=[alternative])],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    string_def = restored.rules[0].strings[0]

    assert isinstance(string_def, HexString)
    assert string_def.tokens == [alternative]


def test_protobuf_serializer_preserves_typed_string_modifier_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="typed_modifiers",
                strings=[
                    PlainString(
                        identifier="$a",
                        value="a",
                        modifiers=[StringModifier.from_name_value("xor", 5)],
                    ),
                    PlainString(
                        identifier="$b",
                        value="b",
                        modifiers=[StringModifier.from_name_value("xor", (1, 3))],
                    ),
                    PlainString(
                        identifier="$c",
                        value="c",
                        modifiers=[StringModifier.from_name_value("base64", "alphabet")],
                    ),
                ],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    restored_strings = restored.rules[0].strings

    assert [string.modifiers[0].value for string in restored_strings] == [
        5,
        (1, 3),
        "alphabet",
    ]


def test_protobuf_deserializes_legacy_xor_modifier_text_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "legacy_modifiers"
    pb_string = pb_rule.strings.add()
    pb_string.identifier = "$a"
    pb_string.plain.value = "a"
    key_modifier = pb_string.plain.modifiers.add()
    key_modifier.name = "xor"
    key_modifier.value = "5"
    range_modifier = pb_string.plain.modifiers.add()
    range_modifier.name = "xor"
    range_modifier.value = "1-3"
    pb_rule.condition.boolean_literal.value = True

    restored = serializer.deserialize(binary_data=pb_file.SerializeToString())
    modifiers = restored.rules[0].strings[0].modifiers

    assert [modifier.value for modifier in modifiers] == [5, (1, 3)]


def test_protobuf_serializer_preserves_extended_expression_roundtrips() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    expressions: list[Expression] = [
        BinaryExpression(
            left=StringOffset("$a", IntegerLiteral(0)),
            operator="==",
            right=IntegerLiteral(0),
        ),
        BinaryExpression(
            left=StringLength("$a", IntegerLiteral(0)),
            operator=">",
            right=IntegerLiteral(1),
        ),
        RegexLiteral(pattern="evil.*", modifiers="i"),
        ParenthesesExpression(BooleanLiteral(True)),
        SetExpression([StringIdentifier("$a"), StringIdentifier("$b")]),
        RangeExpression(IntegerLiteral(0), IntegerLiteral(10)),
        FunctionCall("math.entropy", [IntegerLiteral(0), IntegerLiteral(1)]),
        ArrayAccess(Identifier("arr"), IntegerLiteral(0)),
        MemberAccess(Identifier("pe"), "number_of_sections"),
        ForExpression(
            quantifier="any",
            variable="i",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(2)),
            body=BinaryExpression(Identifier("i"), ">", IntegerLiteral(0)),
        ),
        ForOfExpression(
            quantifier="all",
            string_set=Identifier("them"),
            condition=StringIdentifier("$a"),
        ),
        AtExpression("$a", IntegerLiteral(0)),
        InExpression("$a", RangeExpression(IntegerLiteral(0), IntegerLiteral(10))),
        InExpression(
            OfExpression(IntegerLiteral(1), Identifier("them")),
            RangeExpression(IntegerLiteral(0), IntegerLiteral(10)),
        ),
        OfExpression(IntegerLiteral(1), Identifier("them")),
        DefinedExpression(Identifier("pe")),
        StringOperatorExpression(
            left=StringLiteral("Alpha"),
            operator="icontains",
            right=StringLiteral("alp"),
        ),
    ]

    for expression in expressions:
        ast = YaraFile(rules=[Rule(name="expr", condition=expression)])
        restored = serializer.deserialize(binary_data=serializer.serialize(ast))

        assert restored.rules[0].condition == expression


def test_protobuf_serializer_preserves_expression_quantifiers() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    expressions: list[Expression] = [
        ForExpression(
            quantifier=IntegerLiteral(2),
            variable="i",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(3)),
            body=BooleanLiteral(True),
        ),
        ForOfExpression(
            quantifier=IntegerLiteral(2),
            string_set=Identifier("them"),
            condition=StringIdentifier("$a"),
        ),
    ]

    for expression in expressions:
        ast = YaraFile(rules=[Rule(name="expr", condition=expression)])
        restored = serializer.deserialize(binary_data=serializer.serialize(ast))

        assert restored.rules[0].condition == expression


def test_protobuf_deserializes_legacy_numeric_quantifier_text() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "legacy"
    pb_rule.condition.for_expression.quantifier = "2"
    pb_rule.condition.for_expression.variable = "i"
    pb_rule.condition.for_expression.iterable.range_expression.low.integer_literal.value = 0
    pb_rule.condition.for_expression.iterable.range_expression.high.integer_literal.value = 3
    pb_rule.condition.for_expression.body.boolean_literal.value = True

    restored = serializer.deserialize(binary_data=pb_file.SerializeToString())
    condition = restored.rules[0].condition

    assert isinstance(condition, ForExpression)
    assert condition.quantifier == 2


def test_protobuf_serializer_without_metadata() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = _sample_ast()
    text = serializer.serialize_text(ast)
    assert "format" not in text


def test_protobuf_expression_conversion_paths() -> None:
    pytest.importorskip("yaraast.serialization.yara_ast_pb2")
    from yaraast.serialization import yara_ast_pb2

    serializer = ProtobufSerializer()

    expr_cases: list[tuple[Expression, Callable[[Any], bool]]] = [
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
