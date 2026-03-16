"""Additional Protobuf serializer tests without mocks."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    IntegerLiteral,
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


def test_protobuf_serializer_roundtrip_paths_and_files(tmp_path) -> None:
    serializer = ProtobufSerializer(include_metadata=True)
    rule = Rule(
        name="pb",
        modifiers=["private"],
        tags=[Tag(name="tag")],
        meta={"s": "x", "n": 7, "b": True, "d": 3.5},
        strings=[
            PlainString(
                identifier="$a",
                value="abc",
                modifiers=[StringModifier.from_name_value("nocase")],
            ),
            HexString(
                identifier="$h",
                tokens=[
                    HexByte(value=0x41),
                    HexWildcard(),
                    HexJump(min_jump=1, max_jump=2),
                    HexNibble(high=True, value=0xA),
                ],
                modifiers=[StringModifier.from_name_value("private")],
            ),
            RegexString(
                identifier="$r",
                regex="ab+",
                modifiers=[StringModifier.from_name_value("nocase", "x")],
            ),
        ],
        condition=BinaryExpression(
            left=IntegerLiteral(value=1),
            operator="==",
            right=UnaryExpression(operator="-", operand=IntegerLiteral(value=-1)),
        ),
    )
    ast = YaraFile(
        imports=[Import(module="math", alias="m")],
        includes=[Include(path="inc.yar")],
        rules=[rule, Rule(name="empty", condition=None)],
    )

    bin_path = tmp_path / "ast.pb"
    txt_path = tmp_path / "ast.pb.txt"

    binary = serializer.serialize(ast, output_path=bin_path)
    text = serializer.serialize_text(ast, output_path=txt_path)

    assert binary
    assert "metadata" in text
    assert "alias" in text
    assert bin_path.exists()
    assert txt_path.exists()

    restored = serializer.deserialize(input_path=bin_path)
    assert len(restored.rules) == 2
    assert restored.rules[0].name == "pb"

    stats = serializer.get_serialization_stats(ast)
    assert stats["rules_count"] == 2
    assert stats["includes_count"] == 1
    assert stats["imports_count"] == 1
    assert stats["compression_ratio"] > 0


def test_protobuf_serializer_deserialize_binary_data_directly() -> None:
    serializer = ProtobufSerializer()
    ast = YaraFile(rules=[Rule(name="x", condition=BooleanLiteral(value=True))])
    data = serializer.serialize(ast)
    restored = serializer.deserialize(binary_data=data)
    assert len(restored.rules) == 1
    assert restored.rules[0].name == "x"
