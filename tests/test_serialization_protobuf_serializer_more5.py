"""Additional coverage for protobuf serializer modifier paths."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString
from yaraast.serialization.protobuf_serializer import ProtobufSerializer


def test_protobuf_serializer_hex_modifier_with_value() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="hexmods",
                strings=[
                    HexString(
                        identifier="$h",
                        tokens=[HexByte(value=0x41)],
                        modifiers=[StringModifier.from_name_value("xor", "10-20")],
                    ),
                ],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    text = serializer.serialize_text(ast)
    assert "10-20" in text
